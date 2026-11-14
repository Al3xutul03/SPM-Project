using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Models.ChatGpt;

// ================================================================
// PUBLIC CONTRACTS
// ================================================================

/// <summary>
/// Defines the available Enigma rotor configurations.
/// Rotor IDs correspond to the historical Enigma I / M3 rotors.
/// </summary>
public enum EnigmaRotor
{
    I,
    II,
    III,
    IV,
    V,
    VI,
    VII,
    VIII
}

/// <summary>
/// Defines the supported Enigma reflectors.
/// </summary>
public enum EnigmaReflector
{
    B,
    C
}

/// <summary>
/// Configuration for cryptanalysis.
/// </summary>
public sealed record EnigmaCrackOptions
{
    /// <summary>
    /// Rotor configurations to evaluate, ordered Left, Middle, Right.
    /// </summary>
    public IReadOnlyList<(EnigmaRotor Left, EnigmaRotor Middle, EnigmaRotor Right)>
        RotorOrders
    { get; init; } =
    [
        (EnigmaRotor.I, EnigmaRotor.II, EnigmaRotor.III),
        (EnigmaRotor.I, EnigmaRotor.III, EnigmaRotor.II),
        (EnigmaRotor.II, EnigmaRotor.I, EnigmaRotor.III),
        (EnigmaRotor.II, EnigmaRotor.III, EnigmaRotor.I),
        (EnigmaRotor.III, EnigmaRotor.I, EnigmaRotor.II),
        (EnigmaRotor.III, EnigmaRotor.II, EnigmaRotor.I)
    ];

    /// <summary>
    /// Reflectors to evaluate.
    /// </summary>
    public IReadOnlyList<EnigmaReflector> Reflectors { get; init; } =
    [
        EnigmaReflector.B
    ];

    /// <summary>
    /// Ring settings, ordered Left, Middle, Right.
    /// </summary>
    public IReadOnlyList<(char Left, char Middle, char Right)> RingSettings { get; init; } =
    [
        ('A', 'A', 'A')
    ];

    /// <summary>
    /// Number of random optimization restarts per configuration.
    /// </summary>
    public int Restarts { get; init; } = 20;

    /// <summary>
    /// Number of simulated annealing iterations per restart.
    /// </summary>
    public int IterationsPerRestart { get; init; } = 3000;

    /// <summary>
    /// Maximum number of plugboard connections.
    /// </summary>
    public int MaxPlugboardPairs { get; init; } = 10;

    /// <summary>
    /// Maximum degree of parallelism.
    /// </summary>
    public int MaxDegreeOfParallelism { get; init; } =
        Environment.ProcessorCount;

    /// <summary>
    /// Initial simulated annealing temperature.
    /// </summary>
    public double InitialTemperature { get; init; } = 20.0;

    /// <summary>
    /// Final simulated annealing temperature.
    /// </summary>
    public double FinalTemperature { get; init; } = 0.1;

    /// <summary>
    /// Optional known plugboard connections.
    /// </summary>
    public IReadOnlyList<string> KnownPlugboardPairs { get; init; } =
        Array.Empty<string>();

    /// <summary>
    /// Random seed. Null uses a cryptographically generated seed.
    /// </summary>
    public int? RandomSeed { get; init; }

    /// <summary>
    /// Optional cancellation-independent minimum text length.
    /// </summary>
    public int MinimumCiphertextLength { get; init; } = 20;
}

/// <summary>
/// Describes the result of Enigma cryptanalysis.
/// </summary>
public sealed record EnigmaCrackResult
{
    public required string Plaintext { get; init; }

    public required string Ciphertext { get; init; }

    public required EnigmaSettings Settings { get; init; }

    public required EnigmaRotor LeftRotor { get; init; }

    public required EnigmaRotor MiddleRotor { get; init; }

    public required EnigmaRotor RightRotor { get; init; }

    public required EnigmaReflector Reflector { get; init; }

    public required (char Left, char Middle, char Right) RingSettings { get; init; }

    public required double FitnessScore { get; init; }

    public required double IndexOfCoincidence { get; init; }

    public required int EvaluatedCandidates { get; init; }

    public required TimeSpan ExecutionTime { get; init; }
}

/// <summary>
/// Represents the statistical analysis of a text.
/// </summary>
public sealed record EnigmaTextAnalysis
{
    public required int CharacterCount { get; init; }

    public required double IndexOfCoincidence { get; init; }

    public required double ChiSquared { get; init; }

    public required IReadOnlyDictionary<char, double> LetterFrequencies { get; init; }

    public required double FitnessScore { get; init; }
}

/// <summary>
/// English n-gram statistical model.
/// Scores should preferably be natural logarithms of probabilities.
/// </summary>
public sealed class EnigmaNGramModel
{
    public int N { get; }

    public IReadOnlyDictionary<string, double> Scores { get; }

    public double FloorScore { get; }

    public EnigmaNGramModel(
        int n,
        IReadOnlyDictionary<string, double> scores,
        double floorScore = -15.0)
    {
        if (n < 1 || n > 8)
            throw new ArgumentOutOfRangeException(nameof(n));

        ArgumentNullException.ThrowIfNull(scores);

        var normalized = new Dictionary<string, double>(
            StringComparer.Ordinal);

        foreach (var entry in scores)
        {
            if (entry.Key is null || entry.Key.Length != n)
                continue;

            var key = entry.Key.ToUpperInvariant();

            if (!IsAlphabetic(key))
                continue;

            if (double.IsFinite(entry.Value))
                normalized[key] = entry.Value;
        }

        N = n;
        Scores = new ReadOnlyDictionary<string, double>(normalized);
        FloorScore = floorScore;
    }

    private static bool IsAlphabetic(string value)
    {
        foreach (char c in value)
        {
            if (c is < 'A' or > 'Z')
                return false;
        }

        return true;
    }
}