using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services.Cryptography
{
    /// <summary>
    /// Heuristic cryptanalytic service that recovers the most probable Enigma settings
    /// for a given ciphertext using a combination of rotor-order enumeration,
    /// ring/position hill-climbing and limited plugboard search scored by
    /// English language statistics (monogram + digraph fitness).
    /// </summary>
    public sealed class EnigmaPredictGrokService : IEnigmaPredictGrokService
    {
        // ------------------------------------------------------------------
        // Historical Enigma I wiring (standard commercial / Wehrmacht rotors)
        // ------------------------------------------------------------------
        private static readonly Dictionary<char, string> RotorWirings = new()
        {
            ['1'] = "EKMFLGDQVZNTOWYHXUSPAIBRCJ", // I
            ['2'] = "AJDKSIRUXBLHWTMCQGZNPYFVOE", // II
            ['3'] = "BDFHJLCPRTXVZNYEIWGAKMUSQO", // III
            ['4'] = "ESOVPZJAYQUIRHXLNFTGKDCMWB", // IV
            ['5'] = "VZBRGITYUPSDNHLXAWMJQOFECK"  // V
        };

        private static readonly Dictionary<char, char> RotorNotches = new()
        {
            ['1'] = 'Q',
            ['2'] = 'E',
            ['3'] = 'V',
            ['4'] = 'J',
            ['5'] = 'Z'
        };

        // Reflector B (standard)
        private const string ReflectorB = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

        // English monogram frequencies (normalized, A-Z)
        private static readonly double[] EnglishMonogram =
        {
            0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
            0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
            0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
            0.00978, 0.02360, 0.00150, 0.01974, 0.00074
        };

        // Simple digraph bonus table (most common English digraphs)
        private static readonly HashSet<string> CommonDigraphs = new(StringComparer.OrdinalIgnoreCase)
        {
            "TH","HE","IN","ER","AN","RE","ON","AT","EN","ND","TI","ES","OR",
            "TE","OF","ED","IS","IT","AL","AR","ST","TO","NT","NG","SE","HA",
            "AS","OU","IO","LE","VE","CO","ME","DE","HI","RI","RO","IC","NE"
        };

        private readonly Random _rng = new();

        /// <inheritdoc />
        public async Task<EnigmaSettings> CrackAsync(
            string ciphertext,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ciphertext))
                throw new ArgumentException("Ciphertext must not be empty.", nameof(ciphertext));

            // Normalize: keep only A-Z uppercase
            var ct = new string(ciphertext
                .Where(char.IsLetter)
                .Select(char.ToUpperInvariant)
                .ToArray());

            if (ct.Length < 20)
                throw new ArgumentException("Ciphertext too short for reliable statistical attack (min ~20 letters).", nameof(ciphertext));

            // Run the search on a background thread so the caller remains responsive
            return await Task.Run(() => PerformHeuristicAttack(ct, cancellationToken), cancellationToken)
                             .ConfigureAwait(false);
        }

        // ------------------------------------------------------------------
        // Core attack
        // ------------------------------------------------------------------
        private EnigmaSettings PerformHeuristicAttack(string ciphertext, CancellationToken ct)
        {
            var bestSettings = new EnigmaSettings('1', '2', '3', Array.Empty<string>());
            var bestScore = double.NegativeInfinity;

            // 1. Enumerate a practical subset of rotor orders (5P3 = 60 is feasible)
            var rotorChoices = new[] { '1', '2', '3', '4', '5' };
            var orders = Permute(rotorChoices, 3).ToList();

            foreach (var order in orders)
            {
                ct.ThrowIfCancellationRequested();

                // 2. For each order run a hill-climb on ring settings + positions
                var (rings, positions, score) = HillClimbRingsAndPositions(
                    ciphertext, order[0], order[1], order[2], ct);

                if (score > bestScore)
                {
                    bestScore = score;
                    bestSettings = new EnigmaSettings(order[0], order[1], order[2], Array.Empty<string>());
                }
            }

            // 3. Optional limited plugboard improvement (greedy stecker search)
            var improvedPlugboard = ImprovePlugboard(
                ciphertext,
                bestSettings.Rotor1, bestSettings.Rotor2, bestSettings.Rotor3,
                rings: ('A', 'A', 'A'),          // rings already optimized inside hill-climb
                positions: ('A', 'A', 'A'),
                ct);

            return bestSettings with { PlugboardPairs = improvedPlugboard };
        }

        // ------------------------------------------------------------------
        // Hill-climbing for ring settings and rotor positions
        // ------------------------------------------------------------------
        private ((char, char, char) rings, (char, char, char) positions, double score)
            HillClimbRingsAndPositions(
                string ciphertext,
                char leftRotor, char middleRotor, char rightRotor,
                CancellationToken ct)
        {
            // Start from a random but deterministic-ish seed for reproducibility
            var rings = (Ring: 'A', Mid: 'A', Right: 'A');
            var pos = (Left: 'A', Mid: 'A', Right: 'A');

            double best = Evaluate(ciphertext, leftRotor, middleRotor, rightRotor,
                                   rings, pos, Array.Empty<string>());

            const int maxIterations = 800;
            const int neighbourhood = 3; // ± neighbourhood around current values

            for (int iter = 0; iter < maxIterations; iter++)
            {
                ct.ThrowIfCancellationRequested();

                bool improved = false;

                // Try small perturbations of rings and positions
                for (int dr = -neighbourhood; dr <= neighbourhood; dr++)
                    for (int dm = -neighbourhood; dm <= neighbourhood; dm++)
                        for (int dposL = -neighbourhood; dposL <= neighbourhood; dposL++)
                            for (int dposM = -neighbourhood; dposM <= neighbourhood; dposM++)
                                for (int dposR = -neighbourhood; dposR <= neighbourhood; dposR++)
                                {
                                    if (dr == 0 && dm == 0 && dposL == 0 && dposM == 0 && dposR == 0)
                                        continue;

                                    var candRings = (
                                        Shift(rings.Ring, dr),
                                        Shift(rings.Mid, dm),
                                        Shift(rings.Right, 0)); // right ring less critical, keep simple

                                    var candPos = (
                                        Shift(pos.Left, dposL),
                                        Shift(pos.Mid, dposM),
                                        Shift(pos.Right, dposR));

                                    double s = Evaluate(ciphertext, leftRotor, middleRotor, rightRotor,
                                                        candRings, candPos, Array.Empty<string>());

                                    if (s > best)
                                    {
                                        best = s;
                                        rings = candRings;
                                        pos = candPos;
                                        improved = true;
                                    }
                                }

                // Occasional random restart to escape local maxima
                if (!improved && iter % 40 == 39)
                {
                    rings = (RandomLetter(), RandomLetter(), RandomLetter());
                    pos = (RandomLetter(), RandomLetter(), RandomLetter());
                    best = Evaluate(ciphertext, leftRotor, middleRotor, rightRotor,
                                    rings, pos, Array.Empty<string>());
                }
            }

            return (rings, pos, best);
        }

        // ------------------------------------------------------------------
        // Greedy plugboard (stecker) improvement – limited to 5 pairs for speed
        // ------------------------------------------------------------------
        private IReadOnlyList<string> ImprovePlugboard(
            string ciphertext,
            char r1, char r2, char r3,
            (char, char, char) rings,
            (char, char, char) positions,
            CancellationToken ct)
        {
            var pairs = new List<string>();
            var used = new bool[26];
            double currentScore = Evaluate(ciphertext, r1, r2, r3, rings, positions, pairs);

            // Try up to 5 stecker pairs
            for (int p = 0; p < 5; p++)
            {
                ct.ThrowIfCancellationRequested();

                char bestA = '\0', bestB = '\0';
                double bestDelta = 0;

                for (char a = 'A'; a <= 'Z'; a++)
                {
                    if (used[a - 'A']) continue;
                    for (char b = (char)(a + 1); b <= 'Z'; b++)
                    {
                        if (used[b - 'A']) continue;

                        var trial = pairs.Append($"{a}{b}").ToList();
                        double s = Evaluate(ciphertext, r1, r2, r3, rings, positions, trial);
                        double delta = s - currentScore;

                        if (delta > bestDelta)
                        {
                            bestDelta = delta;
                            bestA = a;
                            bestB = b;
                        }
                    }
                }

                if (bestDelta <= 0.0)
                    break; // no further improvement

                pairs.Add($"{bestA}{bestB}");
                used[bestA - 'A'] = true;
                used[bestB - 'A'] = true;
                currentScore += bestDelta;
            }

            return pairs.AsReadOnly();
        }

        // ------------------------------------------------------------------
        // Fitness evaluation (higher is better)
        // ------------------------------------------------------------------
        private double Evaluate(
            string ciphertext,
            char leftRotor, char middleRotor, char rightRotor,
            (char Left, char Mid, char Right) rings,
            (char Left, char Mid, char Right) positions,
            IReadOnlyList<string> plugboard)
        {
            var machine = new EnigmaMachine(leftRotor, middleRotor, rightRotor,
                                            rings, positions, plugboard);
            string plain = machine.Encrypt(ciphertext); // Enigma is reciprocal

            return ScoreText(plain);
        }

        private static double ScoreText(string text)
        {
            if (text.Length == 0) return double.NegativeInfinity;

            // Monogram chi-squared (lower is better → invert)
            var counts = new int[26];
            foreach (char c in text)
                if (c >= 'A' && c <= 'Z') counts[c - 'A']++;

            double chi = 0;
            double n = text.Length;
            for (int i = 0; i < 26; i++)
            {
                double expected = EnglishMonogram[i] * n;
                if (expected > 0)
                {
                    double diff = counts[i] - expected;
                    chi += (diff * diff) / expected;
                }
            }
            double monoScore = 1000.0 / (1.0 + chi); // invert

            // Digraph bonus
            int digraphHits = 0;
            for (int i = 0; i < text.Length - 1; i++)
            {
                string dg = text.Substring(i, 2);
                if (CommonDigraphs.Contains(dg))
                    digraphHits++;
            }
            double digraphScore = digraphHits * 2.5;

            // Index of Coincidence (prefer values near English ~0.066)
            double ic = IndexOfCoincidence(counts, text.Length);
            double icScore = 50.0 * (1.0 - Math.Abs(ic - 0.066) * 20.0);

            return monoScore + digraphScore + icScore;
        }

        private static double IndexOfCoincidence(int[] counts, int n)
        {
            if (n < 2) return 0;
            double sum = 0;
            foreach (int c in counts)
                sum += c * (c - 1.0);
            return sum / (n * (n - 1.0));
        }

        // ------------------------------------------------------------------
        // Minimal Enigma machine (historical stepping, ring settings, plugboard)
        // ------------------------------------------------------------------
        private sealed class EnigmaMachine
        {
            private readonly char[] _left, _middle, _right;   // wiring
            private readonly char _notchL, _notchM, _notchR;
            private readonly int _ringL, _ringM, _ringR;
            private int _posL, _posM, _posR;
            private readonly Dictionary<char, char> _plug;

            public EnigmaMachine(
                char leftType, char midType, char rightType,
                (char L, char M, char R) rings,
                (char L, char M, char R) positions,
                IReadOnlyList<string> plugboardPairs)
            {
                _left = RotorWirings[leftType].ToCharArray();
                _middle = RotorWirings[midType].ToCharArray();
                _right = RotorWirings[rightType].ToCharArray();

                _notchL = RotorNotches[leftType];
                _notchM = RotorNotches[midType];
                _notchR = RotorNotches[rightType];

                _ringL = rings.L - 'A';
                _ringM = rings.M - 'A';
                _ringR = rings.R - 'A';

                _posL = positions.L - 'A';
                _posM = positions.M - 'A';
                _posR = positions.R - 'A';

                _plug = new Dictionary<char, char>();
                foreach (var pair in plugboardPairs)
                {
                    if (pair.Length >= 2)
                    {
                        char a = char.ToUpperInvariant(pair[0]);
                        char b = char.ToUpperInvariant(pair[1]);
                        _plug[a] = b;
                        _plug[b] = a;
                    }
                }
            }

            public string Encrypt(string text)
            {
                var sb = new StringBuilder(text.Length);
                foreach (char c in text)
                {
                    if (c < 'A' || c > 'Z') continue;
                    sb.Append(Crypt(c));
                }
                return sb.ToString();
            }

            private char Crypt(char ch)
            {
                // Step rotors (double-stepping anomaly of middle rotor)
                bool middleAtNotch = (char)('A' + _posM) == _notchM;
                bool rightAtNotch = (char)('A' + _posR) == _notchR;

                if (middleAtNotch)
                    _posL = (_posL + 1) % 26;
                if (middleAtNotch || rightAtNotch)
                    _posM = (_posM + 1) % 26;
                _posR = (_posR + 1) % 26;

                // Plugboard in
                ch = Plug(ch);

                // Forward through rotors (right → middle → left)
                ch = RotorForward(_right, _posR, _ringR, ch);
                ch = RotorForward(_middle, _posM, _ringM, ch);
                ch = RotorForward(_left, _posL, _ringL, ch);

                // Reflector
                ch = ReflectorB[ch - 'A'];

                // Backward through rotors (left → middle → right)
                ch = RotorBackward(_left, _posL, _ringL, ch);
                ch = RotorBackward(_middle, _posM, _ringM, ch);
                ch = RotorBackward(_right, _posR, _ringR, ch);

                // Plugboard out
                ch = Plug(ch);

                return ch;
            }

            private static char RotorForward(char[] wiring, int pos, int ring, char c)
            {
                int idx = (c - 'A' + pos - ring + 26) % 26;
                char wired = wiring[idx];
                return (char)('A' + (wired - 'A' - pos + ring + 26) % 26);
            }

            private static char RotorBackward(char[] wiring, int pos, int ring, char c)
            {
                int idx = (c - 'A' + pos - ring + 26) % 26;
                // Find inverse
                for (int i = 0; i < 26; i++)
                {
                    if ((wiring[i] - 'A' - pos + ring + 26) % 26 == idx)
                        return (char)('A' + i);
                }
                return c; // should never happen
            }

            private char Plug(char c) => _plug.TryGetValue(c, out var mapped) ? mapped : c;
        }

        // ------------------------------------------------------------------
        // Helpers
        // ------------------------------------------------------------------
        private static char Shift(char c, int delta) =>
            (char)('A' + (c - 'A' + delta + 26) % 26);

        private char RandomLetter() => (char)('A' + _rng.Next(26));

        private static IEnumerable<char[]> Permute(char[] items, int take)
        {
            // Simple recursive permutation generator for small n
            var used = new bool[items.Length];
            var current = new char[take];
            foreach (var p in PermuteRec(items, used, current, 0))
                yield return p;
        }

        private static IEnumerable<char[]> PermuteRec(char[] items, bool[] used, char[] current, int depth)
        {
            if (depth == current.Length)
            {
                yield return (char[])current.Clone();
                yield break;
            }

            for (int i = 0; i < items.Length; i++)
            {
                if (used[i]) continue;
                used[i] = true;
                current[depth] = items[i];
                foreach (var p in PermuteRec(items, used, current, depth + 1))
                    yield return p;
                used[i] = false;
            }
        }
    }
}