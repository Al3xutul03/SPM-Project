using System.Diagnostics;
using System.Text;
using EnigmaLogic.Models;

namespace Tests.EvaluationHarness;

/// <summary>
/// Automated calculators for the four Enigma cryptanalysis evaluation metric categories:
/// 1. Correctness &amp; Accuracy (DSR, State Reconstruction Accuracy, CER)
/// 2. Efficiency (Execution Time, Allocated &amp; Peak Memory)
/// 3. Code Quality (McCabe Cyclomatic Complexity)
/// 4. Robustness (Edge-case handling, Prompt-variation sensitivity drop, 5-run consistency)
/// </summary>
public static class EvaluationMetricsCalculator
{
    // =========================================================================
    // 1. CORRECTNESS & ACCURACY METRICS
    // =========================================================================

    /// <summary>
    /// Computes Decryption Success Rate (DSR) — equivalent to pass@1 (Chen et al., 2021).
    /// Share of runs in which the generated code recovers the exact reference plaintext.
    /// </summary>
    public static double CalculateDecryptionSuccessRate(IEnumerable<bool> runOutcomes)
    {
        ArgumentNullException.ThrowIfNull(runOutcomes);

        int total = 0;
        int successes = 0;

        foreach (bool success in runOutcomes)
        {
            total++;
            if (success)
            {
                successes++;
            }
        }

        return total == 0 ? 0.0 : (double)successes / total;
    }

    /// <summary>
    /// Checks whether the recovered plaintext exactly matches the ground-truth plaintext
    /// after standard A-Z normalization.
    /// </summary>
    public static bool IsExactPlaintextMatch(string referencePlaintext, string? recoveredPlaintext)
    {
        if (recoveredPlaintext is null)
        {
            return false;
        }

        string normRef = NormalizeAlphabet(referencePlaintext);
        string normRec = NormalizeAlphabet(recoveredPlaintext);

        return normRef.Length > 0 && string.Equals(normRef, normRec, StringComparison.Ordinal);
    }

    /// <summary>
    /// Computes the Character Error Rate (CER):
    /// CER = (S + D + I) / N
    /// where S = substitutions, D = deletions, I = insertions (Levenshtein edit distance),
    /// and N = length of the reference text.
    /// </summary>
    public static double CalculateCharacterErrorRate(string referencePlaintext, string? recoveredPlaintext)
    {
        ArgumentNullException.ThrowIfNull(referencePlaintext);

        string reference = NormalizeAlphabet(referencePlaintext);
        string hypothesis = recoveredPlaintext is null ? string.Empty : NormalizeAlphabet(recoveredPlaintext);

        if (reference.Length == 0)
        {
            return hypothesis.Length == 0 ? 0.0 : 1.0;
        }

        int editDistance = ComputeLevenshteinDistance(reference.AsSpan(), hypothesis.AsSpan());
        return (double)editDistance / reference.Length;
    }

    /// <summary>
    /// Computes the Levenshtein edit distance (S + D + I) between two character spans.
    /// </summary>
    public static int ComputeLevenshteinDistance(ReadOnlySpan<char> reference, ReadOnlySpan<char> hypothesis)
    {
        int n = reference.Length;
        int m = hypothesis.Length;

        if (n == 0) return m;
        if (m == 0) return n;

        int[] previousRow = new int[m + 1];
        int[] currentRow = new int[m + 1];

        for (int j = 0; j <= m; j++)
        {
            previousRow[j] = j;
        }

        for (int i = 1; i <= n; i++)
        {
            currentRow[0] = i;

            for (int j = 1; j <= m; j++)
            {
                int cost = reference[i - 1] == hypothesis[j - 1] ? 0 : 1;
                int deletion = previousRow[j] + 1;
                int insertion = currentRow[j - 1] + 1;
                int substitution = previousRow[j - 1] + cost;

                currentRow[j] = Math.Min(Math.Min(deletion, insertion), substitution);
            }

            (previousRow, currentRow) = (currentRow, previousRow);
        }

        return previousRow[m];
    }

    /// <summary>
    /// Computes State Reconstruction Accuracy (Ostwald &amp; Weierud, 2017):
    /// Fraction of Enigma machine settings recovered correctly across:
    /// - Rotor order (Left, Middle, Right)
    /// - Starting positions (Rotor1, Rotor2, Rotor3)
    /// - Ring settings (Left, Middle, Right)
    /// - Plugboard connections (both pair-level recall/precision F1 and 26-letter mapping accuracy)
    /// </summary>
    public static StateReconstructionBreakdown CalculateStateReconstructionAccuracy(
        GroundTruthCase groundTruth,
        CandidatePrediction prediction)
    {
        ArgumentNullException.ThrowIfNull(groundTruth);
        ArgumentNullException.ThrowIfNull(prediction);

        if (prediction.RecoveredSettings is null)
        {
            return new StateReconstructionBreakdown(0, 0, 0, 0, 0, 0);
        }

        // 1. Rotor Order Accuracy (3 slots)
        var expectedOrder = groundTruth.EffectiveRotorOrder;
        var actualOrder = prediction.RecoveredRotorOrder ?? ("I", "II", "III");

        int orderMatches = 0;
        if (string.Equals(expectedOrder.Left, actualOrder.Left, StringComparison.OrdinalIgnoreCase)) orderMatches++;
        if (string.Equals(expectedOrder.Middle, actualOrder.Middle, StringComparison.OrdinalIgnoreCase)) orderMatches++;
        if (string.Equals(expectedOrder.Right, actualOrder.Right, StringComparison.OrdinalIgnoreCase)) orderMatches++;
        double rotorOrderAcc = orderMatches / 3.0;

        // 2. Starting Rotor Positions Accuracy (3 slots)
        int posMatches = 0;
        if (char.ToUpperInvariant(groundTruth.Settings.Rotor1) == char.ToUpperInvariant(prediction.RecoveredSettings.Rotor1)) posMatches++;
        if (char.ToUpperInvariant(groundTruth.Settings.Rotor2) == char.ToUpperInvariant(prediction.RecoveredSettings.Rotor2)) posMatches++;
        if (char.ToUpperInvariant(groundTruth.Settings.Rotor3) == char.ToUpperInvariant(prediction.RecoveredSettings.Rotor3)) posMatches++;
        double rotorPosAcc = posMatches / 3.0;

        // 3. Ring Settings Accuracy (3 slots)
        var expectedRings = groundTruth.EffectiveRingSettings;
        var actualRings = prediction.RecoveredRingSettings ?? ('A', 'A', 'A');

        int ringMatches = 0;
        if (char.ToUpperInvariant(expectedRings.Left) == char.ToUpperInvariant(actualRings.Left)) ringMatches++;
        if (char.ToUpperInvariant(expectedRings.Middle) == char.ToUpperInvariant(actualRings.Middle)) ringMatches++;
        if (char.ToUpperInvariant(expectedRings.Right) == char.ToUpperInvariant(actualRings.Right)) ringMatches++;
        double ringAcc = ringMatches / 3.0;

        // 4. Plugboard Accuracy
        var (pairAcc, mappingAcc) = CalculatePlugboardAccuracy(
            groundTruth.Settings.PlugboardPairs,
            prediction.RecoveredSettings.PlugboardPairs);

        // Overall State Reconstruction Accuracy: unweighted mean of the 4 core state dimensions
        double overall = (rotorOrderAcc + rotorPosAcc + ringAcc + pairAcc) / 4.0;

        return new StateReconstructionBreakdown(
            RotorOrderAccuracy: rotorOrderAcc,
            RotorPositionAccuracy: rotorPosAcc,
            RingSettingAccuracy: ringAcc,
            PlugboardPairAccuracy: pairAcc,
            PlugboardMappingAccuracy: mappingAcc,
            OverallStateAccuracy: overall
        );
    }

    /// <summary>
    /// Compares expected and predicted plugboard configurations.
    /// Returns both unordered pair accuracy (Jaccard/F1 over active stecker pairs) and
    /// 26-contact involution mapping accuracy.
    /// </summary>
    public static (double PairAccuracy, double MappingAccuracy) CalculatePlugboardAccuracy(
        IReadOnlyList<string>? expectedPairs,
        IReadOnlyList<string>? actualPairs)
    {
        HashSet<string> expectedSet = NormalizePlugboardPairs(expectedPairs);
        HashSet<string> actualSet = NormalizePlugboardPairs(actualPairs);

        double pairAccuracy;
        if (expectedSet.Count == 0 && actualSet.Count == 0)
        {
            pairAccuracy = 1.0;
        }
        else if (expectedSet.Count == 0 || actualSet.Count == 0)
        {
            pairAccuracy = 0.0;
        }
        else
        {
            int intersection = expectedSet.Count(actualSet.Contains);
            int union = expectedSet.Count + actualSet.Count - intersection;
            pairAccuracy = union == 0 ? 1.0 : (double)intersection / union;
        }

        int[] expectedMap = BuildPlugboardArray(expectedSet);
        int[] actualMap = BuildPlugboardArray(actualSet);

        int matchingContacts = 0;
        for (int i = 0; i < 26; i++)
        {
            if (expectedMap[i] == actualMap[i])
            {
                matchingContacts++;
            }
        }

        double mappingAccuracy = matchingContacts / 26.0;
        return (pairAccuracy, mappingAccuracy);
    }

    // =========================================================================
    // 2. EFFICIENCY METRICS (EffiBench - Huang et al., 2024)
    // =========================================================================

    /// <summary>
    /// Executes an asynchronous operation while measuring wall-clock execution time,
    /// thread/GC allocated bytes, and process working set delta.
    /// </summary>
    public static async Task<(T Result, TimeSpan Elapsed, long AllocatedBytes, long WorkingSetDelta)> MeasureExecutionEfficiencyAsync<T>(
        Func<Task<T>> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        using Process currentProcess = Process.GetCurrentProcess();
        long workingSetBefore = currentProcess.WorkingSet64;
        long allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);

        long startTimestamp = Stopwatch.GetTimestamp();
        T result = await action().ConfigureAwait(false);
        TimeSpan elapsed = Stopwatch.GetElapsedTime(startTimestamp);

        long allocatedAfter = GC.GetTotalAllocatedBytes(precise: true);
        currentProcess.Refresh();
        long workingSetAfter = currentProcess.WorkingSet64;

        long allocatedBytes = Math.Max(0L, allocatedAfter - allocatedBefore);
        long workingSetDelta = Math.Max(0L, workingSetAfter - workingSetBefore);

        return (result, elapsed, allocatedBytes, workingSetDelta);
    }

    // =========================================================================
    // 3. ROBUSTNESS METRICS (ReCode - Wang et al., 2023; Ouyang et al., 2024)
    // =========================================================================

    /// <summary>
    /// Computes Prompt-Variation Sensitivity: the drop in DSR when the prompt is rephrased
    /// with the same meaning (Wang et al., 2023).
    /// Positive value indicates performance degradation on the rephrased prompt.
    /// </summary>
    public static double CalculatePromptVariationSensitivity(double baselineDsr, double rephrasedPromptDsr)
    {
        return Math.Max(0.0, baselineDsr - rephrasedPromptDsr);
    }

    /// <summary>
    /// Computes Multi-Run Consistency across repeated LLM generations (e.g., 5 runs of the same prompt,
    /// Ouyang et al., 2024).
    /// Returns mean DSR, sample standard deviation, and consistency score (1 - standard deviation).
    /// </summary>
    public static (double MeanDsr, double StandardDeviation, double ConsistencyScore) CalculateMultiRunConsistency(
        IReadOnlyList<double> dsrAcrossRuns)
    {
        ArgumentNullException.ThrowIfNull(dsrAcrossRuns);
        if (dsrAcrossRuns.Count == 0)
        {
            return (0.0, 0.0, 0.0);
        }

        double mean = dsrAcrossRuns.Average();
        if (dsrAcrossRuns.Count == 1)
        {
            return (mean, 0.0, 1.0);
        }

        double sumSquaredDiffs = dsrAcrossRuns.Sum(dsr => (dsr - mean) * (dsr - mean));
        double variance = sumSquaredDiffs / (dsrAcrossRuns.Count - 1);
        double stdDev = Math.Sqrt(variance);

        // Since DSR is in [0, 1], max possible sample stdDev for 5 runs is ~0.5477; clamp consistency to [0, 1].
        double consistency = Math.Clamp(1.0 - stdDev, 0.0, 1.0);
        return (mean, stdDev, consistency);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    public static string NormalizeAlphabet(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            char upper = char.ToUpperInvariant(c);
            if (upper is >= 'A' and <= 'Z')
            {
                sb.Append(upper);
            }
        }

        return sb.ToString();
    }

    private static HashSet<string> NormalizePlugboardPairs(IReadOnlyList<string>? pairs)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (pairs is null)
        {
            return set;
        }

        foreach (string raw in pairs)
        {
            string norm = NormalizeAlphabet(raw);
            if (norm.Length != 2 || norm[0] == norm[1])
            {
                continue;
            }

            char a = norm[0] < norm[1] ? norm[0] : norm[1];
            char b = norm[0] < norm[1] ? norm[1] : norm[0];
            set.Add($"{a}{b}");
        }

        return set;
    }

    private static int[] BuildPlugboardArray(HashSet<string> normalizedPairs)
    {
        int[] map = new int[26];
        for (int i = 0; i < 26; i++)
        {
            map[i] = i;
        }

        foreach (string pair in normalizedPairs)
        {
            int a = pair[0] - 'A';
            int b = pair[1] - 'A';
            map[a] = b;
            map[b] = a;
        }

        return map;
    }
}
