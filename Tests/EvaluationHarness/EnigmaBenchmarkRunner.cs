namespace Tests.EvaluationHarness;

/// <summary>
/// Orchestrates automated evaluation of an <see cref="IEnigmaCrackCandidate"/> (Grok, ChatGPT,
/// Perplexity/DeepSeek, Claude, Gemini) against a ground-truth dataset, edge-case suite, and
/// source file cyclomatic complexity analyzer.
/// </summary>
public sealed class EnigmaBenchmarkRunner
{
    private readonly IReadOnlyList<GroundTruthCase> _groundTruthSuite;
    private readonly IReadOnlyList<(string CaseName, string? CiphertextInput, bool ExpectGraceful)> _edgeCases;

    public EnigmaBenchmarkRunner(
        IReadOnlyList<GroundTruthCase>? groundTruthSuite = null,
        IReadOnlyList<(string CaseName, string? CiphertextInput, bool ExpectGraceful)>? edgeCases = null)
    {
        _groundTruthSuite = groundTruthSuite ?? GroundTruthDatasetGenerator.CreateStandardBenchmarkSuite();
        _edgeCases = edgeCases ?? GroundTruthDatasetGenerator.GetEdgeCaseInputs();
    }

    /// <summary>
    /// Runs the full automated evaluation suite on a candidate solver and optionally computes
    /// cyclomatic complexity for its backing C# source file.
    /// </summary>
    public async Task<ModelEvaluationReport> EvaluateCandidateAsync(
        IEnigmaCrackCandidate candidate,
        string? sourceFilePath = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        var runDetails = new List<SingleRunMetrics>(_groundTruthSuite.Count);

        foreach (GroundTruthCase testCase in _groundTruthSuite)
        {
            SingleRunMetrics metrics = await EvaluateSingleCaseAsync(candidate, testCase, cancellationToken)
                .ConfigureAwait(false);
            runDetails.Add(metrics);
        }

        double edgeCasePassRate = await EvaluateEdgeCaseRobustnessAsync(candidate, cancellationToken)
            .ConfigureAwait(false);

        double avgComplexity = 0.0;
        int maxComplexity = 0;

        if (!string.IsNullOrWhiteSpace(sourceFilePath) && File.Exists(sourceFilePath))
        {
            FileComplexityReport complexityReport = CyclomaticComplexityAnalyzer.AnalyzeFile(sourceFilePath);
            avgComplexity = complexityReport.AverageCyclomaticComplexity;
            maxComplexity = complexityReport.MaxCyclomaticComplexity;
        }

        int totalRuns = runDetails.Count;
        int successfulRuns = runDetails.Count(r => r.IsExactMatch);
        double dsr = EvaluationMetricsCalculator.CalculateDecryptionSuccessRate(runDetails.Select(r => r.IsExactMatch));
        double avgCer = totalRuns == 0 ? 0.0 : runDetails.Average(r => r.CharacterErrorRate);

        var avgBreakdown = totalRuns == 0
            ? new StateReconstructionBreakdown(0, 0, 0, 0, 0, 0)
            : new StateReconstructionBreakdown(
                RotorOrderAccuracy: runDetails.Average(r => r.StateAccuracy.RotorOrderAccuracy),
                RotorPositionAccuracy: runDetails.Average(r => r.StateAccuracy.RotorPositionAccuracy),
                RingSettingAccuracy: runDetails.Average(r => r.StateAccuracy.RingSettingAccuracy),
                PlugboardPairAccuracy: runDetails.Average(r => r.StateAccuracy.PlugboardPairAccuracy),
                PlugboardMappingAccuracy: runDetails.Average(r => r.StateAccuracy.PlugboardMappingAccuracy),
                OverallStateAccuracy: runDetails.Average(r => r.StateAccuracy.OverallStateAccuracy)
            );

        TimeSpan avgTime = totalRuns == 0
            ? TimeSpan.Zero
            : TimeSpan.FromTicks((long)runDetails.Average(r => r.ExecutionTime.Ticks));

        TimeSpan maxTime = totalRuns == 0
            ? TimeSpan.Zero
            : runDetails.Max(r => r.ExecutionTime);

        long avgAllocated = totalRuns == 0 ? 0L : (long)runDetails.Average(r => r.AllocatedBytes);
        long peakAllocated = totalRuns == 0 ? 0L : runDetails.Max(r => r.AllocatedBytes);

        return new ModelEvaluationReport(
            ModelName: candidate.ModelName,
            TotalRuns: totalRuns,
            SuccessfulRuns: successfulRuns,
            DecryptionSuccessRate: dsr,
            AverageCharacterErrorRate: avgCer,
            AverageStateReconstructionAccuracy: avgBreakdown.OverallStateAccuracy,
            AverageStateBreakdown: avgBreakdown,
            AverageExecutionTime: avgTime,
            MaxExecutionTime: maxTime,
            AverageAllocatedBytes: avgAllocated,
            PeakAllocatedBytes: peakAllocated,
            EdgeCasePassRate: edgeCasePassRate,
            AverageCyclomaticComplexity: avgComplexity,
            MaxCyclomaticComplexity: maxComplexity,
            RunDetails: runDetails
        );
    }

    /// <summary>
    /// Evaluates a single ground-truth test case and returns DSR outcome, CER, State Reconstruction Accuracy,
    /// Execution Time, and Memory consumption.
    /// </summary>
    public static async Task<SingleRunMetrics> EvaluateSingleCaseAsync(
        IEnigmaCrackCandidate candidate,
        GroundTruthCase testCase,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var (prediction, elapsed, allocatedBytes, workingSetDelta) =
                await EvaluationMetricsCalculator.MeasureExecutionEfficiencyAsync(
                    () => candidate.CrackAsync(testCase.Ciphertext, cancellationToken))
                .ConfigureAwait(false);

            bool exactMatch = EvaluationMetricsCalculator.IsExactPlaintextMatch(
                testCase.Plaintext,
                prediction.RecoveredPlaintext);

            double cer = EvaluationMetricsCalculator.CalculateCharacterErrorRate(
                testCase.Plaintext,
                prediction.RecoveredPlaintext);

            StateReconstructionBreakdown stateAcc =
                EvaluationMetricsCalculator.CalculateStateReconstructionAccuracy(testCase, prediction);

            return new SingleRunMetrics(
                CaseId: testCase.Id,
                IsExactMatch: exactMatch,
                CharacterErrorRate: cer,
                StateAccuracy: stateAcc,
                ExecutionTime: elapsed,
                AllocatedBytes: allocatedBytes,
                PeakWorkingSetDeltaBytes: workingSetDelta
            );
        }
        catch (Exception ex)
        {
            return new SingleRunMetrics(
                CaseId: testCase.Id,
                IsExactMatch: false,
                CharacterErrorRate: 1.0,
                StateAccuracy: new StateReconstructionBreakdown(0, 0, 0, 0, 0, 0),
                ExecutionTime: TimeSpan.Zero,
                AllocatedBytes: 0,
                PeakWorkingSetDeltaBytes: 0,
                ErrorMessage: $"{ex.GetType().Name}: {ex.Message}"
            );
        }
    }

    /// <summary>
    /// Evaluates edge-case handling rate: the share of unusual inputs (empty, short, non-letter, null)
    /// that either return a sanitized prediction or throw a clean validation exception
    /// (<see cref="ArgumentException"/>, <see cref="ArgumentNullException"/>, <see cref="InvalidOperationException"/>)
    /// rather than crashing with unhandled runtime failures (e.g., <see cref="IndexOutOfRangeException"/>,
    /// <see cref="NullReferenceException"/>, <see cref="DivideByZeroException"/>).
    /// </summary>
    public async Task<double> EvaluateEdgeCaseRobustnessAsync(
        IEnigmaCrackCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        if (_edgeCases.Count == 0)
        {
            return 1.0;
        }

        int passed = 0;

        foreach (var (_, input, _) in _edgeCases)
        {
            try
            {
                CandidatePrediction result = await candidate
                    .CrackAsync(input!, cancellationToken)
                    .ConfigureAwait(false);

                if (result is not null)
                {
                    passed++;
                }
            }
            catch (Exception ex) when (
                ex is ArgumentException
                or ArgumentNullException
                or ArgumentOutOfRangeException
                or InvalidOperationException)
            {
                // Clean, documented guard-clause validation exception counts as proper edge-case handling
                passed++;
            }
            catch
            {
                // Unhandled defect (e.g., IndexOutOfRangeException, NullReferenceException, DivideByZeroException)
            }
        }

        return (double)passed / _edgeCases.Count;
    }
}
