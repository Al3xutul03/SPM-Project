using System.Text;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services.Cryptography;

/// <summary>
/// High-performance heuristic cryptanalysis service for the historical 3-rotor Enigma I.
/// Uses Index-of-Coincidence + English bigram/trigram fitness with a two-phase search
/// (position enumeration + greedy plugboard hill-climb) that finishes in well under
/// a second for typical ciphertext lengths while fully respecting cancellation.
/// </summary>
public sealed class EnigmaPredictGrokService : IEnigmaPredictGrokService
{
    // ──────────────────────────────────────────────────────────────────────
    // Historical wirings (Enigma I, Reflector B)
    // ──────────────────────────────────────────────────────────────────────
    private static readonly IReadOnlyDictionary<string, string> RotorWirings =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["I"] = "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
            ["II"] = "AJDKSIRUXBLHWTMCQGZNPYFVOE",
            ["III"] = "BDFHJLCPRTXVZNYEIWGAKMUSQO",
            ["IV"] = "ESOVPZJAYQUIRHXLNFTGKDCMWB",
            ["V"] = "VZBRGITYUPSDNHLXAWMJQOFECK"
        };

    private static readonly IReadOnlyDictionary<string, char> RotorNotches =
        new Dictionary<string, char>(StringComparer.Ordinal)
        {
            ["I"] = 'Q',
            ["II"] = 'E',
            ["III"] = 'V',
            ["IV"] = 'J',
            ["V"] = 'Z'
        };

    private const string ReflectorB = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

    // English monogram log-probabilities (approximate, normalised) – retained as a light prior
    private static readonly double[] LogMonogram =
    {
        -2.54, -4.20, -3.37, -3.44, -2.40,  // A-E
        -3.93, -3.80, -3.13, -2.83, -5.50,  // F-J
        -4.15, -3.25, -3.48, -2.85, -2.66,  // K-O
        -3.70, -5.30, -2.91, -2.70, -2.55,  // P-T
        -3.75, -4.15, -3.90, -5.00, -3.70,  // U-Y
        -5.80                               // Z
    };

    // High-value English bigrams (log-scale reward; higher = more English-like)
    private static readonly Dictionary<string, double> BigramScore =
        new(StringComparer.Ordinal)
        {
            ["TH"] = 3.2,
            ["HE"] = 3.0,
            ["IN"] = 2.8,
            ["ER"] = 2.7,
            ["AN"] = 2.6,
            ["RE"] = 2.5,
            ["ON"] = 2.4,
            ["AT"] = 2.3,
            ["EN"] = 2.3,
            ["ND"] = 2.2,
            ["TI"] = 2.1,
            ["ES"] = 2.1,
            ["OR"] = 2.0,
            ["TE"] = 2.0,
            ["OF"] = 1.9,
            ["ED"] = 1.9,
            ["IS"] = 1.8,
            ["IT"] = 1.8,
            ["AL"] = 1.7,
            ["AR"] = 1.7,
            ["ST"] = 1.6,
            ["TO"] = 1.6,
            ["NT"] = 1.5,
            ["NG"] = 1.5,
            ["SE"] = 1.4,
            ["HA"] = 1.4,
            ["AS"] = 1.3,
            ["OU"] = 1.3,
            ["IO"] = 1.2,
            ["LE"] = 1.2,
            ["VE"] = 1.1,
            ["CO"] = 1.1,
            ["ME"] = 1.0,
            ["DE"] = 1.0,
            ["HI"] = 0.9,
            ["RI"] = 0.9,
            ["RO"] = 0.8,
            ["IC"] = 0.8,
            ["NE"] = 0.7,
            ["EA"] = 0.7,
            ["RA"] = 0.6,
            ["CE"] = 0.6
        };

    // High-value English trigrams
    private static readonly Dictionary<string, double> TrigramScore =
        new(StringComparer.Ordinal)
        {
            ["THE"] = 4.5,
            ["AND"] = 3.8,
            ["ING"] = 3.5,
            ["ION"] = 3.2,
            ["TIO"] = 3.0,
            ["ENT"] = 2.9,
            ["ATI"] = 2.7,
            ["FOR"] = 2.6,
            ["HER"] = 2.5,
            ["TER"] = 2.4,
            ["HAT"] = 2.3,
            ["THA"] = 2.2,
            ["ERE"] = 2.1,
            ["ATE"] = 2.0,
            ["HIS"] = 1.9,
            ["CON"] = 1.8,
            ["RES"] = 1.7,
            ["VER"] = 1.6,
            ["ALL"] = 1.5,
            ["ONS"] = 1.4,
            ["NCE"] = 1.3,
            ["WIT"] = 1.2,
            ["TIS"] = 1.1,
            ["OFT"] = 1.0,
            ["ITH"] = 0.9,
            ["TED"] = 0.9,
            ["ERS"] = 0.8,
            ["ARE"] = 0.8,
            ["REA"] = 0.7,
            ["COM"] = 0.7
        };

    // ──────────────────────────────────────────────────────────────────────
    // Public API
    // ──────────────────────────────────────────────────────────────────────
    public Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        // Synchronous check so an already-cancelled token throws immediately
        // before any work is queued on the thread-pool.
        cancellationToken.ThrowIfCancellationRequested();

        // Pass the token to Task.Run so cancellation propagates cleanly as
        // OperationCanceledException / TaskCanceledException.
        return Task.Run(() => CrackCore(ciphertext, cancellationToken), cancellationToken);
    }

    private EnigmaSettings CrackCore(string ciphertext, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string clean = Normalise(ciphertext);
        if (clean.Length < 20)
            throw new ArgumentException("Ciphertext too short for reliable cryptanalysis (min 20 letters).", nameof(ciphertext));

        // Fixed historical configuration used by the heuristic:
        // Rotor order I-II-III, rings AAA, Reflector B.
        // (Searching all 60 rotor orders × 26³ rings is deliberately avoided
        //  to keep the whole attack under a second.)
        const string leftName = "I";
        const string midName = "II";
        const string rightName = "III";

        // ── Phase 1: exhaustive search of the 26³ starting positions ──────
        var bestPos = ('A', 'A', 'A');
        double bestScore = double.NegativeInfinity;

        var lockObj = new object();
        Parallel.For(0, 26, new ParallelOptions { CancellationToken = ct }, i =>
        {
            // Re-check at the start of every outer iteration so cancellation
            // is observed promptly and does not become wrapped in AggregateException.
            ct.ThrowIfCancellationRequested();

            for (int j = 0; j < 26; j++)
            {
                for (int k = 0; k < 26; k++)
                {
                    ct.ThrowIfCancellationRequested();

                    char L = (char)('A' + i);
                    char M = (char)('A' + j);
                    char R = (char)('A' + k);

                    string candidate = Decrypt(
                        clean,
                        leftName, midName, rightName,
                        'A', 'A', 'A',          // rings fixed
                        L, M, R,
                        Array.Empty<(char, char)>());

                    double score = Fitness(candidate);
                    if (score > bestScore)
                    {
                        lock (lockObj)
                        {
                            if (score > bestScore)
                            {
                                bestScore = score;
                                bestPos = (L, M, R);
                            }
                        }
                    }
                }
            }
        });

        ct.ThrowIfCancellationRequested();

        // ── Phase 2: greedy hill-climb on the plugboard ───────────────────
        // Allow up to the military maximum of 10 plugboard pairs so that
        // longer messages with denser steckering can still be recovered.
        var plugs = new List<(char, char)>();
        var used = new bool[26];

        for (int pairCount = 0; pairCount < 10; pairCount++)
        {
            ct.ThrowIfCancellationRequested();

            double localBest = bestScore;
            (char, char)? bestPair = null;

            for (char a = 'A'; a <= 'Z'; a++)
            {
                if (used[a - 'A']) continue;
                for (char b = (char)(a + 1); b <= 'Z'; b++)
                {
                    if (used[b - 'A']) continue;

                    var trial = new List<(char, char)>(plugs) { (a, b) };
                    string cand = Decrypt(
                        clean,
                        leftName, midName, rightName,
                        'A', 'A', 'A',
                        bestPos.Item1, bestPos.Item2, bestPos.Item3,
                        trial);

                    double sc = Fitness(cand);
                    if (sc > localBest)
                    {
                        localBest = sc;
                        bestPair = (a, b);
                    }
                }
            }

            if (bestPair is null || localBest <= bestScore + 1e-6)
                break; // no further improvement

            plugs.Add(bestPair.Value);
            used[bestPair.Value.Item1 - 'A'] = true;
            used[bestPair.Value.Item2 - 'A'] = true;
            bestScore = localBest;
        }

        // Convert plug list to the required string representation ("AB", "CD", …)
        var plugStrings = plugs
            .Select(p => $"{p.Item1}{p.Item2}")
            .ToList()
            .AsReadOnly();

        return new EnigmaSettings(
            Rotor1: bestPos.Item1,
            Rotor2: bestPos.Item2,
            Rotor3: bestPos.Item3,
            PlugboardPairs: plugStrings);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Core Enigma simulation (single-pass decrypt)
    // ──────────────────────────────────────────────────────────────────────
    private static string Decrypt(
        string ciphertext,
        string leftName, string midName, string rightName,
        char leftRing, char midRing, char rightRing,
        char leftPos, char midPos, char rightPos,
        IReadOnlyList<(char, char)> plugs)
    {
        // Build fast lookup tables
        int[] plugMap = BuildIdentityMap();
        foreach (var (a, b) in plugs)
        {
            plugMap[a - 'A'] = b - 'A';
            plugMap[b - 'A'] = a - 'A';
        }

        int[] leftWiring = BuildWiring(RotorWirings[leftName]);
        int[] midWiring = BuildWiring(RotorWirings[midName]);
        int[] rightWiring = BuildWiring(RotorWirings[rightName]);
        int[] leftInv = Invert(leftWiring);
        int[] midInv = Invert(midWiring);
        int[] rightInv = Invert(rightWiring);
        int[] reflector = BuildWiring(ReflectorB);

        char leftNotch = RotorNotches[leftName];
        char midNotch = RotorNotches[midName];
        char rightNotch = RotorNotches[rightName];

        // Effective positions after ring settings
        int L = Mod(leftPos - 'A' - (leftRing - 'A'));
        int M = Mod(midPos - 'A' - (midRing - 'A'));
        int R = Mod(rightPos - 'A' - (rightRing - 'A'));

        var sb = new StringBuilder(ciphertext.Length);

        foreach (char ch in ciphertext)
        {
            // ── Stepping (double-step anomaly included) ───────────────────
            bool midAtNotch = (char)('A' + M) == midNotch;
            bool rightAtNotch = (char)('A' + R) == rightNotch;

            if (midAtNotch)
                L = Mod(L + 1);          // left steps when middle is on notch
            if (midAtNotch || rightAtNotch)
                M = Mod(M + 1);          // middle steps on its own notch or when right is on notch
            R = Mod(R + 1);              // right always steps

            // ── Encryption path ───────────────────────────────────────────
            int c = plugMap[ch - 'A'];

            // Right rotor
            c = rightWiring[Mod(c + R)];
            c = Mod(c - R);
            // Middle rotor
            c = midWiring[Mod(c + M)];
            c = Mod(c - M);
            // Left rotor
            c = leftWiring[Mod(c + L)];
            c = Mod(c - L);

            // Reflector
            c = reflector[c];

            // Inverse left
            c = leftInv[Mod(c + L)];
            c = Mod(c - L);
            // Inverse middle
            c = midInv[Mod(c + M)];
            c = Mod(c - M);
            // Inverse right
            c = rightInv[Mod(c + R)];
            c = Mod(c - R);

            c = plugMap[c];
            sb.Append((char)('A' + c));
        }

        return sb.ToString();
    }

    // ──────────────────────────────────────────────────────────────────────
    // Fitness function (Index of Coincidence + bigram / trigram scoring)
    // ──────────────────────────────────────────────────────────────────────
    private static double Fitness(string text)
    {
        if (text.Length < 3) return double.NegativeInfinity;

        int n = text.Length;
        int[] counts = new int[26];
        foreach (char c in text)
            counts[c - 'A']++;

        // Index of Coincidence (primary non-randomness detector)
        double ic = 0.0;
        for (int i = 0; i < 26; i++)
            ic += counts[i] * (counts[i] - 1.0);
        ic /= n * (n - 1.0);

        // Light monogram prior
        double mono = 0.0;
        for (int i = 0; i < 26; i++)
            if (counts[i] > 0)
                mono += counts[i] * LogMonogram[i];
        mono /= n;

        // Bigram score
        double bigram = 0.0;
        for (int i = 0; i < n - 1; i++)
        {
            string bg = text.Substring(i, 2);
            if (BigramScore.TryGetValue(bg, out double s))
                bigram += s;
        }
        bigram /= Math.Max(1, n - 1);

        // Trigram score
        double trigram = 0.0;
        for (int i = 0; i < n - 2; i++)
        {
            string tg = text.Substring(i, 3);
            if (TrigramScore.TryGetValue(tg, out double s))
                trigram += s;
        }
        trigram /= Math.Max(1, n - 2);

        // Weighted combination – IC remains the dominant term; n-grams
        // supply the language model that steers the plugboard hill-climb
        // out of false local optima.
        return 0.45 * ic * 1000.0
             + 0.15 * mono
             + 0.25 * bigram * 10.0
             + 0.15 * trigram * 15.0;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────
    private static string Normalise(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c is >= 'A' and <= 'Z') sb.Append(c);
            else if (c is >= 'a' and <= 'z') sb.Append((char)(c - 32));
        }
        return sb.ToString();
    }

    private static int[] BuildIdentityMap()
    {
        var m = new int[26];
        for (int i = 0; i < 26; i++) m[i] = i;
        return m;
    }

    private static int[] BuildWiring(string wiring)
    {
        var w = new int[26];
        for (int i = 0; i < 26; i++)
            w[i] = wiring[i] - 'A';
        return w;
    }

    private static int[] Invert(int[] wiring)
    {
        var inv = new int[26];
        for (int i = 0; i < 26; i++)
            inv[wiring[i]] = i;
        return inv;
    }

    private static int Mod(int x) => (x % 26 + 26) % 26;
}