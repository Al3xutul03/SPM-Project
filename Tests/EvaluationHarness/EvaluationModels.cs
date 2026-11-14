using EnigmaLogic.Models;

namespace Tests.EvaluationHarness;

/// <summary>
/// Ground-truth test case representing a known plaintext encrypted under known Enigma settings.
/// </summary>
public sealed record GroundTruthCase(
    string Id,
    string Plaintext,
    string Ciphertext,
    EnigmaSettings Settings,
    (string Left, string Middle, string Right)? RotorOrder = null,
    (char Left, char Middle, char Right)? RingSettings = null
)
{
    public (string Left, string Middle, string Right) EffectiveRotorOrder =>
        RotorOrder ?? ("I", "II", "III");

    public (char Left, char Middle, char Right) EffectiveRingSettings =>
        RingSettings ?? ('A', 'A', 'A');
}

/// <summary>
/// Standardized prediction output produced by any evaluated LLM Enigma cryptanalysis service.
/// </summary>
public sealed record CandidatePrediction(
    string RecoveredPlaintext,
    EnigmaSettings? RecoveredSettings = null,
    (string Left, string Middle, string Right)? RecoveredRotorOrder = null,
    (char Left, char Middle, char Right)? RecoveredRingSettings = null
);

/// <summary>
/// Breakdown of State Reconstruction Accuracy across all Enigma configuration components
/// (Ostwald &amp; Weierud, 2017): rotor order, starting positions, ring settings, and plugboard.
/// </summary>
public sealed record StateReconstructionBreakdown(
    double RotorOrderAccuracy,
    double RotorPositionAccuracy,
    double RingSettingAccuracy,
    double PlugboardPairAccuracy,
    double PlugboardMappingAccuracy,
    double OverallStateAccuracy
);

/// <summary>
/// Evaluation metrics recorded for a single decryption run.
/// </summary>
public sealed record SingleRunMetrics(
    string CaseId,
    bool IsExactMatch,
    double CharacterErrorRate,
    StateReconstructionBreakdown StateAccuracy,
    TimeSpan ExecutionTime,
    long AllocatedBytes,
    long PeakWorkingSetDeltaBytes,
    string? ErrorMessage = null
);

/// <summary>
/// Aggregated evaluation metrics across a benchmark suite for a specific LLM model/service.
/// </summary>
public sealed record ModelEvaluationReport(
    string ModelName,
    int TotalRuns,
    int SuccessfulRuns,
    double DecryptionSuccessRate,
    double AverageCharacterErrorRate,
    double AverageStateReconstructionAccuracy,
    StateReconstructionBreakdown AverageStateBreakdown,
    TimeSpan AverageExecutionTime,
    TimeSpan MaxExecutionTime,
    long AverageAllocatedBytes,
    long PeakAllocatedBytes,
    double EdgeCasePassRate,
    double AverageCyclomaticComplexity,
    int MaxCyclomaticComplexity,
    IReadOnlyList<SingleRunMetrics> RunDetails
);

/// <summary>
/// Abstraction representing an LLM-generated Enigma cryptanalysis solver under evaluation.
/// Each colleague's LLM service (Grok, ChatGPT, Claude, Gemini, DeepSeek/Perplexity) can be wrapped
/// in an <see cref="IEnigmaCrackCandidate"/> implementation.
/// </summary>
public interface IEnigmaCrackCandidate
{
    string ModelName { get; }

    Task<CandidatePrediction> CrackAsync(
        string ciphertext,
        CancellationToken cancellationToken = default);
}
