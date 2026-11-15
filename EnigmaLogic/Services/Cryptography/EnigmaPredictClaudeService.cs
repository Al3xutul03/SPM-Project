using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

[assembly: InternalsVisibleTo("Tests")]

namespace EnigmaLogic.Services.Cryptography;

/// <summary>Budget of the attack.</summary>
public sealed record EnigmaCrackOptions
{
    /// <summary>Start positions kept by each scan statistic (IoC, reciprocal, tetragrams) for the plugboard search.</summary>
    public int CandidatesPerStatistic { get; init; } = 48;

    /// <summary>Passes of the quick IoC plugboard climb applied to every start position during the scan.</summary>
    public int ScanClimbSweeps { get; init; } = 1;

    /// <summary>Candidates examined before checking whether one is already good enough to stop.</summary>
    public int BatchSize { get; init; } = 16;

    public int MaxPlugPairs { get; init; } = 13;

    /// <summary>
    /// Log-likelihood cost (nats) a plugboard pair must earn before it is kept: about ln(325), the
    /// information needed to name one pair. Stops short texts from collecting invented pairs.
    /// </summary>
    public double PairCostNats { get; init; } = 6.0;

    /// <summary>Normalized fitness (0 = random, 1 = training text) above which the search stops.</summary>
    public double AcceptFitness { get; init; } = 0.45;

    /// <summary>Leaves a thread-pool thread free; otherwise timers and cancellation are delayed.</summary>
    public int MaxDegreeOfParallelism { get; init; } = Math.Max(1, Environment.ProcessorCount - 1);
}

/// <summary>
/// Full machine key (rotor order, rings, positions, reflector, plugboard). The project's
/// <see cref="EnigmaSettings"/> is the special case rotors I-II-III, rings AAA, reflector B.
/// </summary>
internal sealed record EnigmaKey(
    RotorConfig LeftRotor,
    RotorConfig MiddleRotor,
    RotorConfig RightRotor,
    string Reflector,
    IReadOnlyList<string> PlugboardPairs)
{
    public const string LeftName = "I", MiddleName = "II", RightName = "III", ReflectorName = "B";

    public static EnigmaKey From(EnigmaSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return new EnigmaKey(
            new RotorConfig(LeftName, 'A', settings.Rotor1),
            new RotorConfig(MiddleName, 'A', settings.Rotor2),
            new RotorConfig(RightName, 'A', settings.Rotor3),
            ReflectorName,
            settings.PlugboardPairs ?? Array.Empty<string>());
    }
}

internal sealed class RotorSpec
{
    public string Name { get; }
    public byte[] Forward { get; } = new byte[26 * 26];
    public byte[] Backward { get; } = new byte[26 * 26];

    /// <summary>Bit n is set when the rotor drives its neighbour while the window shows letter n.</summary>
    public int TurnoverMask { get; }

    public RotorSpec(string name, string wiring, string turnovers)
    {
        Name = name;
        foreach (char t in turnovers) TurnoverMask |= 1 << (t - 'A');

        for (int offset = 0; offset < 26; offset++)
        {
            for (int c = 0; c < 26; c++)
            {
                int output = (wiring[(c + offset) % 26] - 'A' - offset + 26) % 26;
                Forward[offset * 26 + c] = (byte)output;
                Backward[offset * 26 + output] = (byte)c;
            }
        }
    }
}

internal static class EnigmaCatalog
{
    public static readonly IReadOnlyDictionary<string, RotorSpec> Rotors = new[]
    {
        new RotorSpec("I", "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
        new RotorSpec("II", "AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
        new RotorSpec("III", "BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
        new RotorSpec("IV", "ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
        new RotorSpec("V", "VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
        new RotorSpec("VI", "JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
        new RotorSpec("VII", "NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
        new RotorSpec("VIII", "FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"),
    }.ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);

    private static readonly byte[] UkwB = ToLookup("YRUHQSLDPXNGOKMIEBFZCWVJAT");
    private static readonly byte[] UkwC = ToLookup("FVPJIAOYEDRZXWGCTKUQSBNMHL");

    public static RotorSpec Rotor(string name) =>
        Rotors.TryGetValue(name?.Trim() ?? string.Empty, out var rotor)
            ? rotor
            : throw new ArgumentException($"Unknown rotor '{name}'.", nameof(name));

    public static byte[] Reflector(string name) =>
        (name ?? string.Empty).Trim().ToUpperInvariant().Replace("-", string.Empty) switch
        {
            "B" or "UKWB" => UkwB,
            "C" or "UKWC" => UkwC,
            _ => throw new ArgumentException($"Unknown reflector '{name}'.", nameof(name)),
        };

    private static byte[] ToLookup(string wiring) => wiring.Select(c => (byte)(c - 'A')).ToArray();
}

/// <summary>Reference Enigma I / M3 engine used to verify the keys found by the attack.</summary>
internal sealed class EnigmaClaudeMachine
{
    private readonly int[] _plugboard = new int[26];
    private RotorSpec _left = null!, _middle = null!, _right = null!;
    private byte[] _reflector = null!;
    private int _ringLeft, _ringMiddle, _ringRight;
    private int _posLeft, _posMiddle, _posRight;
    private bool _configured;

    /// <summary>Project configuration: rotors I-II-III, rings AAA, reflector B.</summary>
    public void Configure(EnigmaSettings settings) => Configure(EnigmaKey.From(settings));

    public void Configure(EnigmaKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var names = new[] { key.LeftRotor.RotorName, key.MiddleRotor.RotorName, key.RightRotor.RotorName };
        if (names.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 3)
            throw new ArgumentException("The three rotors must be distinct.", nameof(key));

        _left = EnigmaCatalog.Rotor(key.LeftRotor.RotorName);
        _middle = EnigmaCatalog.Rotor(key.MiddleRotor.RotorName);
        _right = EnigmaCatalog.Rotor(key.RightRotor.RotorName);
        _reflector = EnigmaCatalog.Reflector(key.Reflector);

        _ringLeft = LetterIndex(key.LeftRotor.RingSetting);
        _ringMiddle = LetterIndex(key.MiddleRotor.RingSetting);
        _ringRight = LetterIndex(key.RightRotor.RingSetting);
        _posLeft = LetterIndex(key.LeftRotor.InitialPosition);
        _posMiddle = LetterIndex(key.MiddleRotor.InitialPosition);
        _posRight = LetterIndex(key.RightRotor.InitialPosition);

        BuildPlugboard(key.PlugboardPairs, _plugboard);
        _configured = true;
    }

    public EnigmaOutput Process(string inputText)
    {
        EnsureConfigured();
        string clean = Sanitize(inputText);
        string output = string.Create(clean.Length, (this, clean), static (span, state) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                state.Item1.Step();
                span[i] = (char)('A' + state.Item1.Encipher(state.clean[i] - 'A'));
            }
        });

        return new EnigmaOutput(output, CurrentPositions());
    }

    /// <summary>Same as <see cref="Process"/>, but records the machine state after every keypress for UI animation.</summary>
    public IReadOnlyList<EnigmaStepState> Trace(string inputText)
    {
        EnsureConfigured();
        string clean = Sanitize(inputText);
        var steps = new EnigmaStepState[clean.Length];

        for (int i = 0; i < clean.Length; i++)
        {
            Step();
            char output = (char)('A' + Encipher(clean[i] - 'A'));
            steps[i] = new EnigmaStepState(CurrentPositions(), clean[i], output);
        }

        return steps;
    }

    /// <summary>Converts to upper case and removes everything outside A-Z.</summary>
    public static string Sanitize(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        Span<char> buffer = text.Length <= 1024 ? stackalloc char[text.Length] : new char[text.Length];
        int length = 0;
        foreach (char c in text.AsSpan())
        {
            if (c is >= 'A' and <= 'Z') buffer[length++] = c;
            else if (c is >= 'a' and <= 'z') buffer[length++] = (char)(c - 32);
        }

        return new string(buffer[..length]);
    }

    internal static void BuildPlugboard(IReadOnlyList<string>? pairs, int[] plugboard)
    {
        for (int i = 0; i < 26; i++) plugboard[i] = i;
        if (pairs is null) return;

        foreach (string pair in pairs)
        {
            string clean = Sanitize(pair);
            if (clean.Length != 2) throw new ArgumentException($"Invalid plugboard pair '{pair}'.", nameof(pairs));

            int a = clean[0] - 'A', b = clean[1] - 'A';
            if (a == b || plugboard[a] != a || plugboard[b] != b)
                throw new ArgumentException($"Plugboard letter used twice in '{pair}'.", nameof(pairs));

            plugboard[a] = b;
            plugboard[b] = a;
        }
    }

    private static int LetterIndex(char letter)
    {
        int index = char.ToUpperInvariant(letter) - 'A';
        return index is >= 0 and < 26 ? index : throw new ArgumentException($"Invalid letter '{letter}'.", nameof(letter));
    }

    private void EnsureConfigured()
    {
        if (!_configured) throw new InvalidOperationException("Machine must be configured by calling Configure().");
    }

    // Stepping happens before enciphering. A middle rotor sitting on its notch advances together
    // with the left rotor regardless of the right rotor: this is the double-step.
    private void Step()
    {
        if ((_middle.TurnoverMask >> _posMiddle & 1) != 0)
        {
            _posMiddle = (_posMiddle + 1) % 26;
            _posLeft = (_posLeft + 1) % 26;
        }
        else if ((_right.TurnoverMask >> _posRight & 1) != 0)
        {
            _posMiddle = (_posMiddle + 1) % 26;
        }

        _posRight = (_posRight + 1) % 26;
    }

    private int Encipher(int c)
    {
        int offsetRight = (_posRight - _ringRight + 26) % 26 * 26;
        int offsetMiddle = (_posMiddle - _ringMiddle + 26) % 26 * 26;
        int offsetLeft = (_posLeft - _ringLeft + 26) % 26 * 26;

        int x = _plugboard[c];
        x = _right.Forward[offsetRight + x];
        x = _middle.Forward[offsetMiddle + x];
        x = _left.Forward[offsetLeft + x];
        x = _reflector[x];
        x = _left.Backward[offsetLeft + x];
        x = _middle.Backward[offsetMiddle + x];
        x = _right.Backward[offsetRight + x];
        return _plugboard[x];
    }

    private (char Left, char Middle, char Right) CurrentPositions() =>
        ((char)('A' + _posLeft), (char)('A' + _posMiddle), (char)('A' + _posRight));
}

/// <summary>
/// Ciphertext-only attack on the project machine (rotors I-II-III, rings AAA, reflector B):
/// scan of the 17,576 start positions (IoC, reciprocal statistic and plugboard-free tetragram score), then
/// plugboard hill climbing with tetragram fitness and a cost per pair. Reliable from roughly 150 letters with
/// 10 plugs; with few plugs much shorter texts work (17 letters without plugboard), while 40–100 letters with
/// 5–10 plugs usually yield a wrong key.
/// </summary>
public sealed class EnigmaPredictClaudeService : IEnigmaPredictClaudeService
{
    /// <summary>Tetragram scoring needs at least four letters.</summary>
    private const int MinimumLength = 4;
    private const int StartCount = 17576;
    private const double Epsilon = 1e-9;

    private static readonly Lazy<NGramModel[]> Models = new(() => new[]
    {
        new NGramModel(EnigmaCorpus.German, separator: null),
        new NGramModel(EnigmaCorpus.German, separator: 'X'),
        new NGramModel(EnigmaCorpus.English, separator: null),
    });

    private static readonly Lazy<byte[]> Table = new(ScramblerTable.Build);
    private static readonly int MiddleMask = EnigmaCatalog.Rotor(EnigmaKey.MiddleName).TurnoverMask;
    private static readonly int RightMask = EnigmaCatalog.Rotor(EnigmaKey.RightName).TurnoverMask;

    private readonly EnigmaCrackOptions _options;

    public EnigmaPredictClaudeService(EnigmaCrackOptions? options = null)
    {
        _options = options ?? new EnigmaCrackOptions();
    }

    public Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        string clean = EnigmaClaudeMachine.Sanitize(ciphertext);
        if (clean.Length < MinimumLength)
            throw new ArgumentException($"The ciphertext must contain at least {MinimumLength} letters A-Z.", nameof(ciphertext));

        return Task.Run(() => Crack(clean, cancellationToken), cancellationToken);
    }

    private EnigmaSettings Crack(string clean, CancellationToken token)
    {
        byte[] cipher = clean.Select(c => (byte)(c - 'A')).ToArray();
        var parallel = new ParallelOptions { CancellationToken = token, MaxDegreeOfParallelism = _options.MaxDegreeOfParallelism };
        Candidate? best = null;
        var solved = new HashSet<int>();

        // The cheap scan suffices for long texts; the scan with a plugboard climb per start position
        // costs seconds but is needed for short texts with many plugs.
        foreach (bool climbScan in new[] { false, true })
        {
            int[] starts = ScanStartPositions(cipher, parallel, climbScan).Where(solved.Add).ToArray();

            // Most promising starts first; each batch is finished, so an early solution stops the search.
            foreach (int[] batch in starts.Chunk(Math.Max(1, _options.BatchSize)))
            {
                var results = new Candidate[batch.Length];
                Parallel.For(0, batch.Length, parallel, () => new Worker(cipher, token), (index, _, worker) =>
                {
                    results[index] = Solve(batch[index], worker);
                    return worker;
                }, _ => { });

                Candidate batchBest = results.MaxBy(candidate => candidate.Fitness)!;
                if (best is null || batchBest.Fitness > best.Fitness) best = batchBest;
                if (best.Fitness >= _options.AcceptFitness) return ToVerifiedSettings(best, clean, cipher);
            }
        }

        return ToVerifiedSettings(best!, clean, cipher);
    }

    // Stage 1: score every start position by IoC, by the reciprocal statistic and (cheap scan only) by the
    // tetragram score without plugboard. Raw IoC is blind with 10 plugs on short texts; with climb = true
    // each start first gets a short IoC plugboard climb.
    private int[] ScanStartPositions(byte[] cipher, ParallelOptions parallel, bool climb)
    {
        int capacity = Math.Max(1, _options.CandidatesPerStatistic);
        int sweeps = Math.Max(1, _options.ScanClimbSweeps);
        var scorer = new CoincidenceScorer();
        NGramModel[] models = Models.Value;
        int[] identity = Enumerable.Range(0, 26).ToArray();
        var coincidence = new List<(int Start, double Score)>();
        var reciprocal = new List<(int Start, double Score)>();
        var language = new List<(int Start, double Score)>();
        object gate = new();

        Parallel.For(0, StartCount, parallel,
            () => (Worker: new Worker(cipher, parallel.CancellationToken),
                   Coincidence: new PriorityQueue<int, double>(capacity + 1),
                   Reciprocal: new PriorityQueue<int, double>(capacity + 1),
                   Language: new PriorityQueue<int, double>(capacity + 1)),
            (start, loopState, local) =>
            {
                local.Worker.BuildPath(start);
                Offer(local.Reciprocal, start, local.Worker.ReciprocalScore(out _), capacity);

                // With few plugs the plaintext already shows through: score it directly.
                if (!climb)
                {
                    local.Worker.Decode(identity);
                    double languageScore = double.MinValue;
                    foreach (NGramModel model in models)
                        languageScore = Math.Max(languageScore, model.Normalize(model.Score(local.Worker.Buffer)));
                    Offer(local.Language, start, languageScore, capacity);
                }

                double coincidenceScore = climb
                    ? ClimbPlugboard(new Candidate(start), scorer, local.Worker, sweeps)
                    : local.Worker.CoincidenceSum();
                Offer(local.Coincidence, start, coincidenceScore, capacity);
                return local;
            },
            local =>
            {
                lock (gate)
                {
                    coincidence.AddRange(local.Coincidence.UnorderedItems.Select(e => (e.Element, e.Priority)));
                    reciprocal.AddRange(local.Reciprocal.UnorderedItems.Select(e => (e.Element, e.Priority)));
                    language.AddRange(local.Language.UnorderedItems.Select(e => (e.Element, e.Priority)));
                }
            });

        // Interleave the rankings so that each statistic contributes its best candidates early.
        // Ties are broken by start position, so the result does not depend on thread scheduling.
        int[][] rankings = new[] { reciprocal, coincidence, language }
            .Select(list => list.OrderByDescending(e => e.Score).ThenBy(e => e.Start).Take(capacity).Select(e => e.Start).ToArray())
            .ToArray();
        int longest = rankings.Max(r => r.Length);
        return Enumerable.Range(0, longest)
            .SelectMany(rank => rankings.Where(r => rank < r.Length).Select(r => r[rank]))
            .Distinct()
            .ToArray();
    }

    private static void Offer(PriorityQueue<int, double> queue, int item, double score, int capacity)
    {
        if (queue.Count < capacity) queue.Enqueue(item, score);
        else if (queue.TryPeek(out _, out double lowest) && score > lowest) queue.DequeueEnqueue(item, score);
    }

    // Stage 2: first pairs from the reciprocal statistic, then IoC climbing, then tetragram climbing per language.
    private Candidate Solve(int start, Worker worker)
    {
        NGramModel[] models = Models.Value;
        worker.BuildPath(start);

        // Scores are means per tetragram, so the cost of a pair is spread over the tetragrams of the text.
        double pairPenalty = _options.PairCostNats / Math.Max(1, worker.Buffer.Length - 3);

        var seeded = new Candidate(start);
        SeedPlugboard(seeded, worker);
        ClimbPlugboard(seeded, new CoincidenceScorer(), worker);

        Candidate? best = null;
        foreach (NGramModel model in models)
        {
            foreach (bool restart in new[] { false, true })
            {
                Candidate attempt = restart ? new Candidate(start) : seeded.Clone();
                double score = ClimbPlugboard(attempt, model, worker, pairPenalty: pairPenalty);
                attempt.Fitness = model.Normalize(score);
                if (best is null || attempt.Fitness > best.Fitness) best = attempt;
            }
        }

        return best!;
    }

    /// <summary>Peak cells (cipher letter, y) of the winning hypothesis point directly at the pairs P(c) = y.</summary>
    private void SeedPlugboard(Candidate candidate, Worker worker)
    {
        worker.ReciprocalScore(out int letter);
        int[] cells = worker.ReciprocalCells(letter);

        bool[] fixedLetter = new bool[26];
        int pairs = 0;
        foreach (int cell in Enumerable.Range(0, cells.Length).Where(i => cells[i] >= 2).OrderByDescending(i => cells[i]))
        {
            int c = cell / 26, y = cell % 26;
            if (fixedLetter[c] || fixedLetter[y]) continue;

            fixedLetter[c] = fixedLetter[y] = true;
            if (c == y || pairs == _options.MaxPlugPairs) continue;

            candidate.Plugboard[c] = y;
            candidate.Plugboard[y] = c;
            pairs++;
        }
    }

    /// <summary>
    /// Hill climbing: for each letter pair tries connecting, disconnecting or rewiring it and keeps the
    /// best improvement, until a local optimum or <paramref name="maxSweeps"/> passes over all pairs.
    /// Expects the worker path to be built for the candidate.
    /// </summary>
    private double ClimbPlugboard(Candidate candidate, TextScorer scorer, Worker worker, int maxSweeps = int.MaxValue, double pairPenalty = 0)
    {
        int[] plug = candidate.Plugboard;
        Span<int> saved = stackalloc int[26];
        Span<int> bestMove = stackalloc int[26];

        worker.Decode(plug);
        double current = scorer.Score(worker.Buffer) - pairPenalty * CountPairs(plug);

        bool improved = true;
        for (int sweep = 0; improved && sweep < maxSweeps; sweep++)
        {
            worker.Token.ThrowIfCancellationRequested();
            improved = false;

            for (int a = 0; a < 25; a++)
            {
                for (int b = a + 1; b < 26; b++)
                {
                    plug.CopyTo(saved);
                    int partnerA = saved[a], partnerB = saved[b];
                    double bestScore = current;
                    bool found = false;

                    if (partnerA == b)
                    {
                        plug[a] = a;
                        plug[b] = b;
                        TryMove(plug, scorer, worker, pairPenalty, ref bestScore, ref found, bestMove);
                    }
                    else
                    {
                        if (partnerA != a) plug[partnerA] = partnerA;
                        if (partnerB != b) plug[partnerB] = partnerB;
                        plug[a] = b;
                        plug[b] = a;
                        if (CountPairs(plug) <= _options.MaxPlugPairs)
                            TryMove(plug, scorer, worker, pairPenalty, ref bestScore, ref found, bestMove);

                        if (partnerA != a && partnerB != b)
                        {
                            plug[partnerA] = partnerB;
                            plug[partnerB] = partnerA;
                            TryMove(plug, scorer, worker, pairPenalty, ref bestScore, ref found, bestMove);
                        }
                    }

                    if (found)
                    {
                        bestMove.CopyTo(plug);
                        current = bestScore;
                        improved = true;
                    }
                    else
                    {
                        saved.CopyTo(plug);
                    }
                }
            }
        }

        return current;
    }

    private static void TryMove(int[] plug, TextScorer scorer, Worker worker, double pairPenalty, ref double bestScore, ref bool found, Span<int> bestMove)
    {
        worker.Decode(plug);
        double score = scorer.Score(worker.Buffer) - pairPenalty * CountPairs(plug);
        if (score > bestScore + Epsilon)
        {
            bestScore = score;
            found = true;
            plug.CopyTo(bestMove);
        }
    }

    private static EnigmaSettings ToVerifiedSettings(Candidate candidate, string clean, byte[] cipher)
    {
        var pairs = new List<string>();
        for (int i = 0; i < 26; i++)
            if (candidate.Plugboard[i] > i)
                pairs.Add($"{(char)('A' + i)}{(char)('A' + candidate.Plugboard[i])}");

        var settings = new EnigmaSettings(
            (char)('A' + candidate.Start / 676),
            (char)('A' + candidate.Start / 26 % 26),
            (char)('A' + candidate.Start % 26),
            pairs);

        // The fast path uses a precomputed table; the reference engine must produce exactly the same text.
        var worker = new Worker(cipher, CancellationToken.None);
        worker.BuildPath(candidate.Start);
        worker.Decode(candidate.Plugboard);
        string fast = string.Create(cipher.Length, worker.Buffer, static (span, buffer) =>
        {
            for (int i = 0; i < span.Length; i++) span[i] = (char)('A' + buffer[i]);
        });

        var machine = new EnigmaClaudeMachine();
        machine.Configure(settings);
        if (machine.Process(clean).OutputText != fast)
            throw new InvalidOperationException("The fast path and the reference engine produced different texts.");

        return settings;
    }

    private static int CountPairs(int[] plug)
    {
        int count = 0;
        for (int i = 0; i < 26; i++)
            if (plug[i] > i) count++;
        return count;
    }

    private sealed class Candidate
    {
        public Candidate(int start)
        {
            Start = start;
            EnigmaClaudeMachine.BuildPlugboard(null, Plugboard);
        }

        /// <summary>Start position: left * 676 + middle * 26 + right.</summary>
        public int Start { get; }
        public int[] Plugboard { get; } = new int[26];
        public double Fitness { get; set; }

        public Candidate Clone()
        {
            var clone = new Candidate(Start) { Fitness = Fitness };
            Plugboard.CopyTo(clone.Plugboard, 0);
            return clone;
        }
    }

    private static class ScramblerTable
    {
        /// <summary>
        /// For each (left, middle, right) rotor state stores the permutation without the plugboard,
        /// so the search never recomputes the rotors. With rings AAA, offsets equal window letters.
        /// </summary>
        public static byte[] Build()
        {
            var table = new byte[StartCount * 26];
            RotorSpec leftRotor = EnigmaCatalog.Rotor(EnigmaKey.LeftName);
            RotorSpec middleRotor = EnigmaCatalog.Rotor(EnigmaKey.MiddleName);
            RotorSpec rightRotor = EnigmaCatalog.Rotor(EnigmaKey.RightName);
            byte[] reflector = EnigmaCatalog.Reflector(EnigmaKey.ReflectorName);
            Span<byte> inner = stackalloc byte[26];

            for (int left = 0; left < 26; left++)
            {
                for (int middle = 0; middle < 26; middle++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        int x = middleRotor.Forward[middle * 26 + c];
                        x = leftRotor.Forward[left * 26 + x];
                        x = reflector[x];
                        x = leftRotor.Backward[left * 26 + x];
                        inner[c] = middleRotor.Backward[middle * 26 + x];
                    }

                    int block = (left * 26 + middle) * 676;
                    for (int right = 0; right < 26; right++)
                    {
                        int row = block + right * 26;
                        int rotor = right * 26;
                        for (int c = 0; c < 26; c++)
                            table[row + c] = rightRotor.Backward[rotor + inner[rightRotor.Forward[rotor + c]]];
                    }
                }
            }

            return table;
        }
    }

    private sealed class Worker
    {
        private readonly byte[] _table = Table.Value;
        private readonly byte[] _cipher;
        private readonly int[] _path;
        private readonly int[] _cipherRows;
        private readonly int[] _cells = new int[676];
        private readonly int[] _letterCounts = new int[26];

        public Worker(byte[] cipher, CancellationToken token)
        {
            _cipher = cipher;
            _path = new int[cipher.Length];
            _cipherRows = cipher.Select(c => c * 26).ToArray();
            Buffer = new byte[cipher.Length];
            Token = token;
        }

        public byte[] Buffer { get; }
        public CancellationToken Token { get; }

        /// <summary>Table row of every keypress, after stepping (including the double-step).</summary>
        public void BuildPath(int start)
        {
            int left = start / 676, middle = start / 26 % 26, right = start % 26;
            Span<int> path = _path;
            for (int i = 0; i < path.Length; i++)
            {
                if ((MiddleMask >> middle & 1) != 0)
                {
                    middle = middle == 25 ? 0 : middle + 1;
                    left = left == 25 ? 0 : left + 1;
                }
                else if ((RightMask >> right & 1) != 0)
                {
                    middle = middle == 25 ? 0 : middle + 1;
                }

                right = right == 25 ? 0 : right + 1;
                path[i] = ((left * 26 + middle) * 26 + right) * 26;
            }
        }

        public long CoincidenceSum()
        {
            ReadOnlySpan<int> path = _path;
            ReadOnlySpan<byte> cipher = _cipher;
            ReadOnlySpan<byte> table = _table;
            Span<int> counts = _letterCounts;
            counts.Clear();

            for (int i = 0; i < path.Length; i++) counts[table[path[i] + cipher[i]]]++;

            long sum = 0;
            foreach (int count in counts) sum += count * (count - 1);
            return sum;
        }

        /// <summary>
        /// The scrambler S_i is an involution, so p_i = P(S_i(P(c_i))) implies P(c_i) = S_i(P(p_i)).
        /// For a hypothesis e = P(frequent letter), the pairs (c_i, S_i(e)) pile up on the cells (c, P(c)).
        /// </summary>
        public long ReciprocalScore(out int bestLetter)
        {
            ReadOnlySpan<int> path = _path;
            ReadOnlySpan<int> rows = _cipherRows;
            ReadOnlySpan<byte> table = _table;
            Span<int> cells = _cells;
            long best = -1;
            bestLetter = 0;

            for (int e = 0; e < 26; e++)
            {
                cells.Clear();
                long sum = 0;
                for (int i = 0; i < path.Length; i++)
                    sum += cells[rows[i] + table[path[i] + e]]++;

                if (sum > best) (best, bestLetter) = (sum, e);
            }

            return best;
        }

        public int[] ReciprocalCells(int letter)
        {
            Array.Clear(_cells);
            for (int i = 0; i < _path.Length; i++) _cells[_cipherRows[i] + _table[_path[i] + letter]]++;
            return _cells;
        }

        public void Decode(int[] plug)
        {
            ReadOnlySpan<int> path = _path;
            ReadOnlySpan<byte> cipher = _cipher;
            Span<byte> buffer = Buffer;
            byte[] table = _table;

            for (int i = 0; i < path.Length; i++)
                buffer[i] = (byte)plug[table[path[i] + plug[cipher[i]]]];
        }
    }

    private abstract class TextScorer
    {
        public abstract double Score(ReadOnlySpan<byte> text);
    }

    private sealed class CoincidenceScorer : TextScorer
    {
        public override double Score(ReadOnlySpan<byte> text)
        {
            Span<int> counts = stackalloc int[26];
            foreach (byte letter in text) counts[letter]++;

            long sum = 0;
            foreach (int count in counts) sum += count * (count - 1);
            return (double)sum / (text.Length * (text.Length - 1));
        }
    }

    /// <summary>
    /// Interpolated third-order Markov model: log P(d|abc) for every tetragram, trained
    /// on the embedded corpus. The score is the mean log-likelihood per tetragram.
    /// </summary>
    private sealed class NGramModel : TextScorer
    {
        private readonly float[] _logProbability = new float[456976];
        private readonly double _randomMean;
        private readonly double _languageMean;

        public NGramModel(string corpus, char? separator)
        {
            byte[] text = Encode(corpus, separator);
            var unigrams = new int[26];
            var bigrams = new int[676];
            var trigrams = new int[17576];
            var tetragrams = new int[456976];

            for (int i = 0; i < text.Length; i++)
            {
                int code = text[i];
                unigrams[code]++;
                if (i < 1) continue;
                code += text[i - 1] * 26;
                bigrams[code]++;
                if (i < 2) continue;
                code += text[i - 2] * 676;
                trigrams[code]++;
                if (i < 3) continue;
                code += text[i - 3] * 17576;
                tetragrams[code]++;
            }

            double total = text.Length, sum = 0;
            for (int code = 0; code < _logProbability.Length; code++)
            {
                int d = code % 26, cd = code % 676, bcd = code % 17576;
                double p =
                    0.55 * Ratio(tetragrams[code], trigrams[code / 26]) +
                    0.25 * Ratio(trigrams[bcd], bigrams[bcd / 26]) +
                    0.12 * Ratio(bigrams[cd], unigrams[cd / 26]) +
                    0.06 * unigrams[d] / total +
                    0.02 / 26;
                double log = Math.Log(p);
                _logProbability[code] = (float)log;
                sum += log;
            }

            _randomMean = sum / _logProbability.Length;
            _languageMean = Score(text);
        }

        public override double Score(ReadOnlySpan<byte> text)
        {
            if (text.Length < 4) return double.NegativeInfinity;

            float[] table = _logProbability;
            int code = text[0] * 676 + text[1] * 26 + text[2];
            double sum = 0;
            for (int i = 3; i < text.Length; i++)
            {
                code = code % 17576 * 26 + text[i];
                sum += table[code];
            }

            return sum / (text.Length - 3);
        }

        /// <summary>0 = random, 1 = as likely as the training text; comparable across languages.</summary>
        public double Normalize(double score) => (score - _randomMean) / (_languageMean - _randomMean);

        private static double Ratio(int numerator, int denominator) =>
            denominator == 0 ? 0 : (double)numerator / denominator;

        private static byte[] Encode(string corpus, char? separator)
        {
            string spaced = separator is char s
                ? string.Join(s, corpus.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                : corpus;
            return EnigmaClaudeMachine.Sanitize(spaced).Select(c => (byte)(c - 'A')).ToArray();
        }
    }
}

/// <summary>Original training text for the n-gram models. Umlauts are transliterated, as in Enigma practice.</summary>
internal static class EnigmaCorpus
{
    public const string German = """
        Die Abteilung meldet um sechs Uhr dreissig dass die vorderen Stellungen an der Strasse nach Norden gehalten werden.
        Der Feind hat waehrend der Nacht mit schwachen Kraeften angegriffen und wurde durch unser Feuer abgewiesen.
        Die zweite Kompanie geht bei Tagesanbruch ueber den Fluss vor und besetzt die Hoehe oestlich des Dorfes.
        Nachschub an Munition und Treibstoff wird bis heute Abend zum Bahnhof gebracht. Die Verbindung zum Regiment
        ist seit gestern unterbrochen, deshalb sollen alle Meldungen ueber die Funkstelle der Division gegeben werden.
        Der Kommandeur befiehlt, dass die Truppen sofort die neue Linie erreichen und dort bis zum Eintreffen der
        Verstaerkung bleiben. Aufklaerung nach Westen hat keine feindlichen Panzer festgestellt, jedoch stehen starke
        Artillerie und Infanterie suedlich der Bruecke. Das Wetter ist schlecht, der Regen macht alle Wege fuer
        Fahrzeuge fast unbrauchbar. Flugzeuge koennen deshalb erst am Nachmittag starten. Das Unterseeboot hat am
        Morgen einen grossen Geleitzug gesichtet und laeuft mit hoher Fahrt nach Sueden. Kurs und Geschwindigkeit des
        Gegners werden jede Stunde gemeldet. Alle Boote in diesem Seegebiet sollen sich an der befohlenen Position
        sammeln und auf weitere Befehle warten. Die Besatzung ist gesund, der Brennstoff reicht noch fuer zehn Tage.
        Im Hafen liegen drei Schiffe, die mit Getreide und Kohle beladen werden. Nach dem Bericht der Wetterstation
        nimmt der Wind aus Nordwest zu und die See wird in der kommenden Nacht schwerer.
        Es war einmal ein alter Mann, der wohnte mit seiner Tochter in einem kleinen Haus am Rande des Waldes. Jeden
        Morgen ging er zur Arbeit und kam erst spaet wieder nach Hause. Die Kinder aus der Stadt besuchten ihn gern,
        weil er viele Geschichten kannte und ihnen immer etwas Neues erzaehlen konnte. Heute wissen wir, dass die
        Menschen schon vor langer Zeit versucht haben, ihre Nachrichten geheim zu halten. Eine Maschine, die jeden
        Buchstaben durch einen anderen ersetzt, schien damals unmoeglich zu brechen. Doch die Mathematiker fanden
        Schwaechen in dem Verfahren und entwickelten neue Methoden. Wer eine Sprache lernen will, muss viel lesen,
        sprechen und schreiben. In der Schule haben die Schueler auch gelernt, wie man einen Brief an einen Freund
        verfasst und welche Woerter man dabei verwenden sollte. Die Regierung hat in dieser Woche beschlossen, neue
        Gesetze fuer die Wirtschaft vorzubereiten, und die Zeitungen berichten ausfuehrlich ueber die Folgen fuer
        das ganze Land. Waehrend der Sommer in diesem Jahr besonders warm war, fiel im Winter ungewoehnlich viel Schnee.
        """;

    public const string English = """
        The history of secret writing is older than most people think, and every generation has believed that its own
        methods could never be broken. When a message is sent across a great distance, there is always a chance that
        somebody else will read it, so people have looked for ways to hide the meaning from anyone without the key.
        During the war the army and the navy depended on radio, which meant that every signal could be heard by the
        enemy. Operators worked through the night, writing down long groups of letters and passing them to the men
        and women whose job it was to find some pattern in them. They knew that the machine would never turn a letter
        into itself, and this small weakness gave them a place to begin. Their work was kept secret for many years
        after the fighting had ended, and few of them ever talked about what they had done.
        The commanding officer reported that the first battalion had reached the river before dawn and would hold the
        bridge until further orders arrived from headquarters. Supplies of food and fuel were expected by the evening,
        although the weather had made the roads almost impossible for heavy vehicles. Ships in the northern convoy
        changed course at noon after a submarine was seen on the surface near the harbour.
        In the small town where she grew up, there was a school, a church and a shop that sold almost everything. Her
        father worked at the mill and her mother taught the younger children to read. On summer evenings the whole
        family would walk down to the water and talk about what they wanted to do when the harvest was over. Years later
        she moved to the city, found a position at a large company and began to study science at night. It was not an
        easy life, but she often said that learning something new was the best thing that could happen to anyone.
        Today computers can test millions of possible solutions in a single second, and students are able to repeat in
        an afternoon what once required a building full of equipment. The government has announced new plans for the
        national economy, while researchers continue to publish important results about language, information and the
        structure of the natural world. If you want to understand how a system works, you should first try to take it
        apart, then ask which of its parts are really necessary and how they have been connected together.
        """;
}
