using EnigmaLogic.Models;
using EnigmaLogic.Models.ChatGpt;
using EnigmaLogic.Services.Abstractions;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;

namespace EnigmaLogic.Services;

/// <summary>
/// Enigma I / M3 cryptanalysis service.
///
/// Implements:
/// - Historical Enigma I / M3 rotor wirings.
/// - Rotors I through VIII.
/// - Reflectors UKW-B and UKW-C.
/// - Correct double-stepping mechanism.
/// - Ringstellung.
/// - Grundstellung.
/// - Steckerbrett.
/// - Index of Coincidence.
/// - Chi-squared analysis.
/// - N-gram / tetragram fitness.
/// - Simulated annealing and hill-climbing optimization.
///
/// Rotor order is always Left, Middle, Right.
/// </summary>
public sealed class EnigmaPredictChatGPTService
    : IEnigmaPredictChatGPTService
{
    private const int AlphabetSize = 26;

    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static readonly double[] EnglishFrequencies =
    [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702,
        0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
        0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
        0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
        0.02758, 0.00978, 0.02360, 0.00150, 0.01974,
        0.00074
    ];

    private static readonly IReadOnlyDictionary<EnigmaRotor, RotorDefinition>
        Rotors = new Dictionary<EnigmaRotor, RotorDefinition>
        {
            [EnigmaRotor.I] = new("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
            [EnigmaRotor.II] = new("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
            [EnigmaRotor.III] = new("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
            [EnigmaRotor.IV] = new("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
            [EnigmaRotor.V] = new("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
            [EnigmaRotor.VI] = new("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
            [EnigmaRotor.VII] = new("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
            [EnigmaRotor.VIII] = new("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM")
        };

    private static readonly IReadOnlyDictionary<EnigmaReflector, string>
        Reflectors = new Dictionary<EnigmaReflector, string>
        {
            [EnigmaReflector.B] = "YRUHQSLDPXNGOKMIEBFZCWVJAT",
            [EnigmaReflector.C] = "FVPJIAOYEDRZXWGCTKUQSBNMHL"
        };

    private readonly EnigmaNGramModel? _defaultModel;

    public EnigmaPredictChatGPTService(
        EnigmaNGramModel? defaultModel = null)
    {
        _defaultModel = defaultModel;
    }

    // ============================================================
    // PUBLIC API
    // ============================================================

    public EnigmaOutput Simulate(
        string input,
        EnigmaSettings settings,
        EnigmaRotor leftRotor = EnigmaRotor.I,
        EnigmaRotor middleRotor = EnigmaRotor.II,
        EnigmaRotor rightRotor = EnigmaRotor.III,
        EnigmaReflector reflector = EnigmaReflector.B,
        (char Left, char Middle, char Right)? ringSettings = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(settings);

        ValidatePosition(settings.Rotor1, nameof(settings.Rotor1));
        ValidatePosition(settings.Rotor2, nameof(settings.Rotor2));
        ValidatePosition(settings.Rotor3, nameof(settings.Rotor3));

        var rings = ringSettings ?? ('A', 'A', 'A');

        ValidatePosition(rings.Left, nameof(ringSettings));
        ValidatePosition(rings.Middle, nameof(ringSettings));
        ValidatePosition(rings.Right, nameof(ringSettings));

        int[] plugboard = CreatePlugboard(settings.PlugboardPairs);

        var machine = new EnigmaMachine(
            leftRotor,
            middleRotor,
            rightRotor,
            reflector,
            settings.Rotor1 - 'A',
            settings.Rotor2 - 'A',
            settings.Rotor3 - 'A',
            rings.Left - 'A',
            rings.Middle - 'A',
            rings.Right - 'A',
            plugboard);

        string sanitized = Sanitize(input);

        char[] output = new char[sanitized.Length];

        for (int i = 0; i < sanitized.Length; i++)
            output[i] = (char)('A' + machine.Transform(sanitized[i] - 'A'));

        return new EnigmaOutput(
            new string(output),
            (
                (char)('A' + machine.LeftPosition),
                (char)('A' + machine.MiddlePosition),
                (char)('A' + machine.RightPosition)
            ));
    }

    public double CalculateIndexOfCoincidence(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        string sanitized = Sanitize(text);

        if (sanitized.Length < 2)
            return 0;

        Span<int> frequencies = stackalloc int[AlphabetSize];

        foreach (char c in sanitized)
            frequencies[c - 'A']++;

        long numerator = 0;

        foreach (int frequency in frequencies)
            numerator += (long)frequency * (frequency - 1);

        long n = sanitized.Length;

        return (double)numerator / (n * (n - 1));
    }

    public double CalculateFitness(
        string text,
        EnigmaNGramModel model)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(model);

        string sanitized = Sanitize(text);

        if (sanitized.Length < model.N)
            return model.FloorScore;

        return CalculateNGramFitness(sanitized.AsSpan(), model);
    }

    public EnigmaTextAnalysis AnalyzeText(
        string text,
        EnigmaNGramModel? model = null)
    {
        ArgumentNullException.ThrowIfNull(text);

        string sanitized = Sanitize(text);

        Span<int> counts = stackalloc int[AlphabetSize];

        foreach (char c in sanitized)
            counts[c - 'A']++;

        int length = sanitized.Length;

        var frequencies = new Dictionary<char, double>();

        double chiSquared = 0;

        for (int i = 0; i < AlphabetSize; i++)
        {
            double actual = length == 0
                ? 0
                : (double)counts[i] / length;

            frequencies[(char)('A' + i)] = actual;

            double expected = length * EnglishFrequencies[i];

            if (expected > 0)
            {
                double difference = counts[i] - expected;

                chiSquared += difference * difference / expected;
            }
        }

        return new EnigmaTextAnalysis
        {
            CharacterCount = length,
            IndexOfCoincidence = CalculateIndexOfCoincidence(sanitized),
            ChiSquared = chiSquared,
            LetterFrequencies = frequencies,
            FitnessScore = model is null
                ? 0
                : CalculateFitness(sanitized, model)
        };
    }

    // ============================================================
    // CRYPTANALYSIS
    // ============================================================

    public async Task<EnigmaCrackResult> CrackAsync(
        string ciphertext,
        EnigmaCrackOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        options ??= new EnigmaCrackOptions();

        ValidateOptions(options);

        string encrypted = Sanitize(ciphertext);

        if (encrypted.Length < options.MinimumCiphertextLength)
        {
            throw new ArgumentException(
                $"Ciphertext must contain at least " +
                $"{options.MinimumCiphertextLength} alphabetic characters.",
                nameof(ciphertext));
        }

        if (_defaultModel is null)
        {
            throw new InvalidOperationException(
                "An English n-gram model must be supplied through " +
                "the constructor before running cryptanalysis.");
        }

        var stopwatch = Stopwatch.StartNew();

        var configurations =
            from order in options.RotorOrders
            from reflector in options.Reflectors
            from rings in options.RingSettings
            select new SearchConfiguration(
                order.Left,
                order.Middle,
                order.Right,
                reflector,
                rings.Left - 'A',
                rings.Middle - 'A',
                rings.Right - 'A');

        var results = new ConcurrentBag<SearchResult>();

        int evaluated = 0;

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.MaxDegreeOfParallelism,
            CancellationToken = cancellationToken
        };

        var configurationArray = configurations.ToArray();

        await Task.Run(() =>
        {
            Parallel.ForEach(
                configurationArray,
                parallelOptions,
                configuration =>
                {
                    for (int restart = 0;
                         restart < options.Restarts;
                         restart++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        int seed = options.RandomSeed.HasValue
                            ? HashCode.Combine(
                                options.RandomSeed.Value,
                                configuration.GetHashCode(),
                                restart)
                            : RandomNumberGenerator.GetInt32(int.MaxValue);

                        var random = new Random(seed);

                        SearchResult result = OptimizeConfiguration(
                            encrypted,
                            configuration,
                            options,
                            random,
                            cancellationToken);

                        results.Add(result);

                        Interlocked.Increment(ref evaluated);
                    }
                });
        }, cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        stopwatch.Stop();

        SearchResult best = results
            .OrderByDescending(x => x.Fitness)
            .First();

        return new EnigmaCrackResult
        {
            Ciphertext = encrypted,
            Plaintext = best.Plaintext,

            Settings = new EnigmaSettings(
                (char)('A' + best.LeftPosition),
                (char)('A' + best.MiddlePosition),
                (char)('A' + best.RightPosition),
                best.PlugboardPairs),

            LeftRotor = best.Configuration.Left,
            MiddleRotor = best.Configuration.Middle,
            RightRotor = best.Configuration.Right,

            Reflector = best.Configuration.Reflector,

            RingSettings = (
                (char)('A' + best.Configuration.LeftRing),
                (char)('A' + best.Configuration.MiddleRing),
                (char)('A' + best.Configuration.RightRing)
            ),

            FitnessScore = best.Fitness,

            IndexOfCoincidence =
                CalculateIndexOfCoincidence(best.Plaintext),

            EvaluatedCandidates = evaluated,

            ExecutionTime = stopwatch.Elapsed
        };
    }

    // ============================================================
    // OPTIMIZATION ENGINE
    // ============================================================

    private SearchResult OptimizeConfiguration(
        string ciphertext,
        SearchConfiguration configuration,
        EnigmaCrackOptions options,
        Random random,
        CancellationToken cancellationToken)
    {
        int leftPosition = random.Next(26);
        int middlePosition = random.Next(26);
        int rightPosition = random.Next(26);

        int[] plugboard = CreatePlugboard(
            options.KnownPlugboardPairs);

        string plaintext = Decrypt(
            ciphertext,
            configuration,
            leftPosition,
            middlePosition,
            rightPosition,
            plugboard);

        double currentFitness = CalculateNGramFitness(
            plaintext.AsSpan(),
            _defaultModel!);

        var best = new SearchResult(
            configuration,
            leftPosition,
            middlePosition,
            rightPosition,
            (int[])plugboard.Clone(),
            plaintext,
            currentFitness);

        int[] currentPlugboard = (int[])plugboard.Clone();

        double temperature = options.InitialTemperature;

        double coolingRate = Math.Pow(
            options.FinalTemperature / options.InitialTemperature,
            1.0 / options.IterationsPerRestart);

        for (int iteration = 0;
             iteration < options.IterationsPerRestart;
             iteration++)
        {
            if ((iteration & 127) == 0)
                cancellationToken.ThrowIfCancellationRequested();

            int previousLeft = leftPosition;
            int previousMiddle = middlePosition;
            int previousRight = rightPosition;

            int[] previousPlugboard =
                (int[])currentPlugboard.Clone();

            // Mutate rotor starting positions or plugboard.
            int mutation = random.Next(100);

            if (mutation < 55)
            {
                switch (random.Next(3))
                {
                    case 0:
                        leftPosition = random.Next(26);
                        break;

                    case 1:
                        middlePosition = random.Next(26);
                        break;

                    default:
                        rightPosition = random.Next(26);
                        break;
                }
            }
            else
            {
                MutatePlugboard(
                    currentPlugboard,
                    options.MaxPlugboardPairs,
                    random);
            }

            plaintext = Decrypt(
                ciphertext,
                configuration,
                leftPosition,
                middlePosition,
                rightPosition,
                currentPlugboard);

            double newFitness = CalculateNGramFitness(
                plaintext.AsSpan(),
                _defaultModel!);

            double difference = newFitness - currentFitness;

            bool accept = difference >= 0 ||
                random.NextDouble() <
                Math.Exp(difference / Math.Max(temperature, 0.000001));

            if (accept)
            {
                currentFitness = newFitness;
            }
            else
            {
                leftPosition = previousLeft;
                middlePosition = previousMiddle;
                rightPosition = previousRight;

                currentPlugboard = previousPlugboard;
            }

            if (currentFitness > best.Fitness)
            {
                best = new SearchResult(
                    configuration,
                    leftPosition,
                    middlePosition,
                    rightPosition,
                    (int[])currentPlugboard.Clone(),
                    plaintext,
                    currentFitness);
            }

            temperature *= coolingRate;
        }

        return best;
    }

    /// <summary>
    /// Applies a random valid plugboard mutation.
    ///
    /// A plugboard is an involution: if A maps to B,
    /// B must map to A.
    /// </summary>
    private static void MutatePlugboard(
        int[] plugboard,
        int maximumPairs,
        Random random)
    {
        Span<int> free = stackalloc int[26];

        int freeCount = 0;
        int pairCount = 0;

        for (int i = 0; i < 26; i++)
        {
            if (plugboard[i] == i)
                free[freeCount++] = i;

            if (plugboard[i] > i)
                pairCount++;
        }

        int operation = random.Next(3);

        if (operation == 0 && pairCount > 0)
        {
            // Remove an existing pair.
            int selected = random.Next(26);

            if (plugboard[selected] == selected)
                return;

            int partner = plugboard[selected];

            plugboard[selected] = selected;
            plugboard[partner] = partner;

            return;
        }

        if (freeCount >= 2 && pairCount < maximumPairs)
        {
            // Create a new pair.
            int firstIndex = random.Next(freeCount);
            int first = free[firstIndex];

            free[firstIndex] = free[freeCount - 1];
            freeCount--;

            int second = free[random.Next(freeCount)];

            plugboard[first] = second;
            plugboard[second] = first;

            return;
        }

        // Swap the partners of two existing connections.
        Span<int> connected = stackalloc int[26];

        int connectedCount = 0;

        for (int i = 0; i < 26; i++)
        {
            if (plugboard[i] > i)
                connected[connectedCount++] = i;
        }

        if (connectedCount < 2)
            return;

        int firstPair = connected[random.Next(connectedCount)];

        int secondPair;

        do
        {
            secondPair = connected[random.Next(connectedCount)];
        }
        while (firstPair == secondPair);

        int firstPartner = plugboard[firstPair];
        int secondPartner = plugboard[secondPair];

        plugboard[firstPair] = secondPartner;
        plugboard[secondPartner] = firstPair;

        plugboard[secondPair] = firstPartner;
        plugboard[firstPartner] = secondPair;
    }

    // ============================================================
    // ENIGMA MACHINE
    // ============================================================

    private sealed class EnigmaMachine
    {
        private readonly RotorDefinition _left;
        private readonly RotorDefinition _middle;
        private readonly RotorDefinition _right;

        private readonly int _leftRing;
        private readonly int _middleRing;
        private readonly int _rightRing;

        private readonly int[] _reflector;
        private readonly int[] _plugboard;

        public int LeftPosition { get; private set; }

        public int MiddlePosition { get; private set; }

        public int RightPosition { get; private set; }

        public EnigmaMachine(
            EnigmaRotor left,
            EnigmaRotor middle,
            EnigmaRotor right,
            EnigmaReflector reflector,
            int leftPosition,
            int middlePosition,
            int rightPosition,
            int leftRing,
            int middleRing,
            int rightRing,
            int[] plugboard)
        {
            _left = Rotors[left];
            _middle = Rotors[middle];
            _right = Rotors[right];

            _reflector = Reflectors[reflector]
                .Select(c => c - 'A')
                .ToArray();

            _leftRing = leftRing;
            _middleRing = middleRing;
            _rightRing = rightRing;

            LeftPosition = leftPosition;
            MiddlePosition = middlePosition;
            RightPosition = rightPosition;

            _plugboard = plugboard;
        }

        public int Transform(int input)
        {
            // Rotor stepping happens BEFORE electrical traversal.
            StepRotors();

            // Steckerbrett: input plugboard.
            int signal = _plugboard[input];

            // Forward traversal: Right -> Middle -> Left.
            signal = Forward(signal, _right, RightPosition, _rightRing);
            signal = Forward(signal, _middle, MiddlePosition, _middleRing);
            signal = Forward(signal, _left, LeftPosition, _leftRing);

            // Reflector.
            signal = _reflector[signal];

            // Reverse traversal: Left -> Middle -> Right.
            signal = Reverse(signal, _left, LeftPosition, _leftRing);
            signal = Reverse(signal, _middle, MiddlePosition, _middleRing);
            signal = Reverse(signal, _right, RightPosition, _rightRing);

            // Steckerbrett: output plugboard.
            return _plugboard[signal];
        }

        /// <summary>
        /// Implements the Enigma double-stepping mechanism.
        ///
        /// The middle rotor advances when:
        /// - The right rotor is at its notch.
        /// - The middle rotor is at its own notch.
        ///
        /// The left rotor advances when the middle rotor is at its notch.
        /// The right rotor always advances.
        ///
        /// For VI, VII and VIII, there are two turnover positions.
        /// </summary>
        private void StepRotors()
        {
            bool middleAtNotch =
                IsAtNotch(_middle, MiddlePosition, _middleRing);

            bool rightAtNotch =
                IsAtNotch(_right, RightPosition, _rightRing);

            if (middleAtNotch)
                LeftPosition = (LeftPosition + 1) % 26;

            if (rightAtNotch || middleAtNotch)
                MiddlePosition = (MiddlePosition + 1) % 26;

            RightPosition = (RightPosition + 1) % 26;
        }

        private static bool IsAtNotch(
            RotorDefinition rotor,
            int position,
            int ring)
        {
            // The turnover notch is fixed to the rotor body.
            // The visible window position is offset by Ringstellung.
            foreach (char notch in rotor.Notches)
            {
                int notchPosition = notch - 'A';

                if ((position - ring + 26) % 26 == notchPosition)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Forward rotor transformation.
        ///
        /// y = (W[x + P - R] - P + R) mod 26
        /// </summary>
        private static int Forward(
            int signal,
            RotorDefinition rotor,
            int position,
            int ring)
        {
            int offset = (position - ring + 26) % 26;

            int shifted = (signal + offset) % 26;

            int wired = rotor.Forward[shifted];

            return (wired - offset + 26) % 26;
        }

        /// <summary>
        /// Reverse rotor transformation using the inverse wiring.
        /// </summary>
        private static int Reverse(
            int signal,
            RotorDefinition rotor,
            int position,
            int ring)
        {
            int offset = (position - ring + 26) % 26;

            int shifted = (signal + offset) % 26;

            int wired = rotor.Reverse[shifted];

            return (wired - offset + 26) % 26;
        }
    }

    private sealed class RotorDefinition
    {
        public int[] Forward { get; }

        public int[] Reverse { get; }

        public string Notches { get; }

        public RotorDefinition(string wiring, string notches)
        {
            if (wiring.Length != 26)
                throw new ArgumentException("Invalid rotor wiring.");

            Forward = wiring.Select(c => c - 'A').ToArray();

            Reverse = new int[26];

            for (int i = 0; i < 26; i++)
                Reverse[Forward[i]] = i;

            Notches = notches;
        }
    }

    // ============================================================
    // DECRYPTION
    // ============================================================

    private static string Decrypt(
        string ciphertext,
        SearchConfiguration configuration,
        int leftPosition,
        int middlePosition,
        int rightPosition,
        int[] plugboard)
    {
        var machine = new EnigmaMachine(
            configuration.Left,
            configuration.Middle,
            configuration.Right,
            configuration.Reflector,
            leftPosition,
            middlePosition,
            rightPosition,
            configuration.LeftRing,
            configuration.MiddleRing,
            configuration.RightRing,
            plugboard);

        char[] output = new char[ciphertext.Length];

        for (int i = 0; i < ciphertext.Length; i++)
        {
            int encrypted = ciphertext[i] - 'A';

            output[i] = (char)(
                'A' + machine.Transform(encrypted));
        }

        return new string(output);
    }

    // ============================================================
    // STATISTICAL FITNESS
    // ============================================================

    /// <summary>
    /// Calculates average n-gram log-likelihood.
    ///
    /// Fitness = sum(log(P(ngram))) / number of n-grams.
    ///
    /// Higher values indicate a more probable plaintext.
    /// </summary>
    private static double CalculateNGramFitness(
        ReadOnlySpan<char> text,
        EnigmaNGramModel model)
    {
        int n = model.N;

        if (text.Length < n)
            return model.FloorScore;

        double score = 0;

        int count = text.Length - n + 1;

        for (int i = 0; i < count; i++)
        {
            Span<char> gram = stackalloc char[n];

            text.Slice(i, n).CopyTo(gram);

            string key = new(gram);

            score += model.Scores.TryGetValue(key, out double value)
                ? value
                : model.FloorScore;
        }

        return score / count;
    }

    // ============================================================
    // PLUGBOARD
    // ============================================================

    private static int[] CreatePlugboard(
        IReadOnlyList<string>? pairs)
    {
        int[] plugboard = new int[26];

        for (int i = 0; i < 26; i++)
            plugboard[i] = i;

        if (pairs is null)
            return plugboard;

        foreach (string pair in pairs)
        {
            if (string.IsNullOrWhiteSpace(pair))
                throw new ArgumentException("Invalid plugboard pair.");

            string normalized = pair.Trim().ToUpperInvariant();

            if (normalized.Length != 2 ||
                normalized[0] is < 'A' or > 'Z' ||
                normalized[1] is < 'A' or > 'Z')
            {
                throw new ArgumentException(
                    $"Invalid plugboard pair: {pair}");
            }

            int first = normalized[0] - 'A';
            int second = normalized[1] - 'A';

            if (first == second)
                throw new ArgumentException(
                    "A letter cannot be connected to itself.");

            if (plugboard[first] != first ||
                plugboard[second] != second)
            {
                throw new ArgumentException(
                    "A letter cannot participate in multiple plugboard pairs.");
            }

            plugboard[first] = second;
            plugboard[second] = first;
        }

        return plugboard;
    }

    private static IReadOnlyList<string> ExtractPlugboardPairs(
        int[] plugboard)
    {
        var pairs = new List<string>();

        for (int i = 0; i < 26; i++)
        {
            if (plugboard[i] > i)
            {
                pairs.Add(
                    $"{(char)('A' + i)}{(char)('A' + plugboard[i])}");
            }
        }

        return pairs.AsReadOnly();
    }

    // ============================================================
    // INPUT VALIDATION AND NORMALIZATION
    // ============================================================

    /// <summary>
    /// Retains only ASCII A-Z characters.
    /// Removes whitespace, punctuation, digits and non-ASCII letters.
    /// </summary>
    private static string Sanitize(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        char[] buffer = new char[input.Length];

        int length = 0;

        foreach (char c in input)
        {
            if (c is >= 'A' and <= 'Z')
            {
                buffer[length++] = c;
            }
            else if (c is >= 'a' and <= 'z')
            {
                buffer[length++] = (char)(c - 32);
            }
        }

        return new string(buffer, 0, length);
    }

    private static void ValidatePosition(char position, string name)
    {
        if (position is < 'A' or > 'Z')
        {
            throw new ArgumentException(
                "Position must be an uppercase ASCII letter A-Z.",
                name);
        }
    }

    private static void ValidateOptions(EnigmaCrackOptions options)
    {
        if (options.RotorOrders is null ||
            options.RotorOrders.Count == 0)
        {
            throw new ArgumentException(
                "At least one rotor order is required.");
        }

        if (options.Reflectors is null ||
            options.Reflectors.Count == 0)
        {
            throw new ArgumentException(
                "At least one reflector is required.");
        }

        if (options.RingSettings is null ||
            options.RingSettings.Count == 0)
        {
            throw new ArgumentException(
                "At least one ring configuration is required.");
        }

        if (options.Restarts < 1)
            throw new ArgumentOutOfRangeException(nameof(options.Restarts));

        if (options.IterationsPerRestart < 1)
            throw new ArgumentOutOfRangeException(
                nameof(options.IterationsPerRestart));

        if (options.MaxPlugboardPairs is < 0 or > 13)
            throw new ArgumentOutOfRangeException(
                nameof(options.MaxPlugboardPairs));

        if (options.MaxDegreeOfParallelism < 1)
            throw new ArgumentOutOfRangeException(
                nameof(options.MaxDegreeOfParallelism));

        if (options.MinimumCiphertextLength < 1)
            throw new ArgumentOutOfRangeException(
                nameof(options.MinimumCiphertextLength));

        if (options.InitialTemperature <= 0 ||
            options.FinalTemperature <= 0 ||
            options.FinalTemperature > options.InitialTemperature)
        {
            throw new ArgumentException(
                "Invalid simulated annealing temperatures.");
        }

        foreach (var order in options.RotorOrders)
        {
            if (!Rotors.ContainsKey(order.Left) ||
                !Rotors.ContainsKey(order.Middle) ||
                !Rotors.ContainsKey(order.Right))
            {
                throw new ArgumentException(
                    "Invalid rotor configuration.");
            }

            if (order.Left == order.Middle ||
                order.Left == order.Right ||
                order.Middle == order.Right)
            {
                throw new ArgumentException(
                    "A rotor cannot be used more than once.");
            }
        }

        foreach (var rings in options.RingSettings)
        {
            ValidatePosition(rings.Left, nameof(options.RingSettings));
            ValidatePosition(rings.Middle, nameof(options.RingSettings));
            ValidatePosition(rings.Right, nameof(options.RingSettings));
        }

        foreach (var reflector in options.Reflectors)
        {
            if (!Reflectors.ContainsKey(reflector))
                throw new ArgumentException("Invalid reflector.");
        }

        CreatePlugboard(options.KnownPlugboardPairs);

        if (options.KnownPlugboardPairs.Count > options.MaxPlugboardPairs)
        {
            throw new ArgumentException(
                "Known plugboard pairs exceed MaxPlugboardPairs.");
        }
    }

    // ============================================================
    // INTERNAL SEARCH MODELS
    // ============================================================

    private sealed record SearchConfiguration(
        EnigmaRotor Left,
        EnigmaRotor Middle,
        EnigmaRotor Right,
        EnigmaReflector Reflector,
        int LeftRing,
        int MiddleRing,
        int RightRing);

    private sealed record SearchResult(
        SearchConfiguration Configuration,
        int LeftPosition,
        int MiddlePosition,
        int RightPosition,
        int[] Plugboard,
        string Plaintext,
        double Fitness)
    {
        public IReadOnlyList<string> PlugboardPairs =>
            ExtractPlugboardPairs(Plugboard);
    }
}