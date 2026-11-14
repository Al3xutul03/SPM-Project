using EnigmaLogic.Models;
using EnigmaLogic.Services;

namespace Tests.EvaluationHarness;

/// <summary>
/// Automated MSTest suite verifying and running all evaluation metrics from the evaluation document:
/// - Correctness &amp; Accuracy: Decryption Success Rate (DSR), State Reconstruction Accuracy, Character Error Rate (CER)
/// - Efficiency: Execution Time and Allocated/Peak Memory (EffiBench)
/// - Code Quality: McCabe Cyclomatic Complexity per function
/// - Robustness: Edge-case handling, Prompt-variation sensitivity (ReCode), and 5-run consistency
/// </summary>
[TestClass]
public class EvaluationHarnessTests
{
    public TestContext? TestContext { get; set; }

    // =========================================================================
    // 1. CORRECTNESS & ACCURACY TESTS
    // =========================================================================

    [TestMethod]
    public void CharacterErrorRate_IdenticalNormalizedTexts_ReturnsZero()
    {
        double cer = EvaluationMetricsCalculator.CalculateCharacterErrorRate(
            "WETTERBERICHTKLAR",
            "  wetterbericht klar! ");

        Assert.AreEqual(0.0, cer, 1e-9);
    }

    [TestMethod]
    public void CharacterErrorRate_KnownSubstitutionsDeletionsInsertions_MatchesFormula()
    {
        // Reference N = 10 ("ABCDEFGHIJ")
        // Hypothesis has 2 substitutions ('A'->'Z', 'B'->'Y') and 1 deletion ('J' missing) => S+D+I = 3
        // CER = 3 / 10 = 0.30
        double cer = EvaluationMetricsCalculator.CalculateCharacterErrorRate(
            "ABCDEFGHIJ",
            "ZYCDEFGHI");

        Assert.AreEqual(0.30, cer, 1e-9);
    }

    [TestMethod]
    public void DecryptionSuccessRate_MixedOutcomes_ComputesPassAt1Equivalent()
    {
        bool[] outcomes = [true, false, true, true, false];
        double dsr = EvaluationMetricsCalculator.CalculateDecryptionSuccessRate(outcomes);

        Assert.AreEqual(0.60, dsr, 1e-9);
    }

    [TestMethod]
    public void StateReconstructionAccuracy_PartialRecovery_ComputesAccurateComponentBreakdown()
    {
        var groundTruth = new GroundTruthCase(
            Id: "TEST-STATE",
            Plaintext: "ATTACKATDAWN",
            Ciphertext: "XYZ",
            Settings: new EnigmaSettings('A', 'B', 'C', ["AB", "CD", "EF", "GH"]),
            RotorOrder: ("I", "II", "III"),
            RingSettings: ('A', 'A', 'A')
        );

        // Candidate recovers:
        // - 3/3 Rotor order ("I", "II", "III") -> 1.0
        // - 2/3 Starting positions ('A', 'B', 'Z') -> 2/3
        // - 3/3 Ring settings ('A', 'A', 'A') -> 1.0
        // - 2 of 4 Plugboard pairs ("BA", "CD") -> Jaccard = 2 / 4 = 0.5
        var prediction = new CandidatePrediction(
            RecoveredPlaintext: "ATTACKATDAWX",
            RecoveredSettings: new EnigmaSettings('A', 'B', 'Z', ["BA", "CD"]),
            RecoveredRotorOrder: ("I", "II", "III"),
            RecoveredRingSettings: ('A', 'A', 'A')
        );

        StateReconstructionBreakdown breakdown =
            EvaluationMetricsCalculator.CalculateStateReconstructionAccuracy(groundTruth, prediction);

        Assert.AreEqual(1.0, breakdown.RotorOrderAccuracy, 1e-6);
        Assert.AreEqual(2.0 / 3.0, breakdown.RotorPositionAccuracy, 1e-6);
        Assert.AreEqual(1.0, breakdown.RingSettingAccuracy, 1e-6);
        Assert.AreEqual(0.5, breakdown.PlugboardPairAccuracy, 1e-6);

        double expectedOverall = (1.0 + (2.0 / 3.0) + 1.0 + 0.5) / 4.0;
        Assert.AreEqual(expectedOverall, breakdown.OverallStateAccuracy, 1e-6);
    }

    // =========================================================================
    // 2. EFFICIENCY TESTS (EffiBench)
    // =========================================================================

    [TestMethod]
    public async Task MeasureExecutionEfficiency_TracksTimeAndAllocatedMemory()
    {
        var (result, elapsed, allocatedBytes, _) =
            await EvaluationMetricsCalculator.MeasureExecutionEfficiencyAsync(async () =>
            {
                byte[] buffer = new byte[64 * 1024];
                buffer[0] = 42;
                await Task.Yield();
                return buffer[0];
            });

        Assert.AreEqual((byte)42, result);
        Assert.IsGreaterThan(TimeSpan.Zero, elapsed, "Elapsed time should be positive.");
        Assert.IsGreaterThanOrEqualTo(64 * 1024, allocatedBytes, $"Expected at least 65536 allocated bytes, got {allocatedBytes}.");
    }

    // =========================================================================
    // 3. CODE QUALITY TESTS (McCabe Cyclomatic Complexity)
    // =========================================================================

    [TestMethod]
    public void CyclomaticComplexityAnalyzer_EvaluatesEnigmaSimServiceSourceFile()
    {
        string servicePath = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "EnigmaLogic", "Services", "EnigmaSimService.cs"));

        Assert.IsTrue(File.Exists(servicePath), $"Could not locate {servicePath}");

        FileComplexityReport report = CyclomaticComplexityAnalyzer.AnalyzeFile(servicePath);

        Assert.IsGreaterThan(0, report.MethodCount, "Expected methods to be discovered in EnigmaSimService.cs.");
        Assert.IsGreaterThanOrEqualTo(1.0, report.AverageCyclomaticComplexity);
        Assert.IsLessThanOrEqualTo(
            CyclomaticComplexityAnalyzer.McCabeRecommendedUpperBound,
            report.AverageCyclomaticComplexity,
            $"Average cyclomatic complexity ({report.AverageCyclomaticComplexity:F2}) exceeded McCabe's bound of 10.");

        TestContext?.WriteLine(
            $"File: {report.FilePath} | Methods: {report.MethodCount} | " +
            $"Avg CC: {report.AverageCyclomaticComplexity:F2} | Max CC: {report.MaxCyclomaticComplexity}");
    }

    // =========================================================================
    // 4. ROBUSTNESS TESTS (Edge Cases, Prompt Sensitivity, 5-Run Consistency)
    // =========================================================================

    [TestMethod]
    public void EnigmaSimService_EdgeCases_HandlesEmptyShortNonAlphaAndInvalidSettings()
    {
        var sim = new EnigmaSimService();
        sim.Configure(new EnigmaSettings('A', 'A', 'A', []), RandomSettings: false);

        // Non-letter characters only -> normalizes to empty output without crashing
        string nonAlphaOutput = sim.Process("12345!@#$%");
        Assert.AreEqual(string.Empty, nonAlphaOutput);

        // Single character -> valid 1-char ciphertext, not self-encrypted
        sim.Configure(new EnigmaSettings('A', 'A', 'A', []), RandomSettings: false);
        string singleCharOutput = sim.Process("A");
        Assert.AreEqual(1, singleCharOutput.Length);
        Assert.AreNotEqual('A', singleCharOutput[0]);

        // Conflicting plugboard pairs ("AB" and "AC") -> throws ArgumentException
        Assert.ThrowsExactly<ArgumentException>(() =>
            sim.Configure(new EnigmaSettings('A', 'A', 'A', ["AB", "AC"]), RandomSettings: false));

        // Invalid plugboard pair length ("ABC") -> throws ArgumentException
        Assert.ThrowsExactly<ArgumentException>(() =>
            sim.Configure(new EnigmaSettings('A', 'A', 'A', ["ABC"]), RandomSettings: false));
    }

    [TestMethod]
    public void Robustness_PromptVariationAndFiveRunConsistency_CalculatesExpectedMetrics()
    {
        // Prompt-variation sensitivity (Wang et al., 2023): drop from 0.80 to 0.65 => 0.15
        double drop = EvaluationMetricsCalculator.CalculatePromptVariationSensitivity(0.80, 0.65);
        Assert.AreEqual(0.15, drop, 1e-9);

        // 5 repeated runs of the same prompt (Ouyang et al., 2024)
        double[] fiveRunDsrs = [0.80, 0.80, 0.60, 0.80, 1.00];
        var (meanDsr, stdDev, consistencyScore) =
            EvaluationMetricsCalculator.CalculateMultiRunConsistency(fiveRunDsrs);

        Assert.AreEqual(0.80, meanDsr, 1e-9);
        Assert.AreEqual(Math.Sqrt(0.02), stdDev, 1e-6);
        Assert.AreEqual(1.0 - Math.Sqrt(0.02), consistencyScore, 1e-6);
    }

    // =========================================================================
    // 5. END-TO-END BENCHMARK RUNNER TEST
    // =========================================================================

    [TestMethod]
    public async Task BenchmarkRunner_EndToEndEvaluation_ProducesCompleteModelReport()
    {
        IReadOnlyList<GroundTruthCase> suite = GroundTruthDatasetGenerator.CreateStandardBenchmarkSuite();
        var runner = new EnigmaBenchmarkRunner(suite);

        string servicePath = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "EnigmaLogic", "Services", "EnigmaSimService.cs"));

        // Evaluate a reference oracle candidate (simulating 100% recovery) and a partial/imperfect candidate
        var oracleCandidate = new ReferenceOracleCandidate("Reference-Oracle", suite);
        var noisyCandidate = new ImperfectSimulatedCandidate("Simulated-LLM-Candidate", suite);

        ModelEvaluationReport oracleReport = await runner.EvaluateCandidateAsync(oracleCandidate, servicePath);
        ModelEvaluationReport noisyReport = await runner.EvaluateCandidateAsync(noisyCandidate, servicePath);

        Assert.AreEqual(1.0, oracleReport.DecryptionSuccessRate, 1e-9);
        Assert.AreEqual(0.0, oracleReport.AverageCharacterErrorRate, 1e-9);
        Assert.AreEqual(1.0, oracleReport.AverageStateReconstructionAccuracy, 1e-9);
        Assert.AreEqual(1.0, oracleReport.EdgeCasePassRate, 1e-9);

        Assert.IsTrue(noisyReport.DecryptionSuccessRate is > 0.0 and < 1.0);
        Assert.IsGreaterThan(0.0, noisyReport.AverageCharacterErrorRate);
        Assert.IsTrue(noisyReport.AverageStateReconstructionAccuracy is > 0.0 and < 1.0);

        TestContext?.WriteLine($"[{oracleReport.ModelName}] DSR={oracleReport.DecryptionSuccessRate:P1}, CER={oracleReport.AverageCharacterErrorRate:P2}, StateAcc={oracleReport.AverageStateReconstructionAccuracy:P1}, AvgTime={oracleReport.AverageExecutionTime.TotalMilliseconds:F2}ms, EdgePass={oracleReport.EdgeCasePassRate:P0}, AvgCC={oracleReport.AverageCyclomaticComplexity:F2}");
        TestContext?.WriteLine($"[{noisyReport.ModelName}] DSR={noisyReport.DecryptionSuccessRate:P1}, CER={noisyReport.AverageCharacterErrorRate:P2}, StateAcc={noisyReport.AverageStateReconstructionAccuracy:P1}, AvgTime={noisyReport.AverageExecutionTime.TotalMilliseconds:F2}ms, EdgePass={noisyReport.EdgeCasePassRate:P0}, AvgCC={noisyReport.AverageCyclomaticComplexity:F2}");
    }

    // =========================================================================
    // TEST CANDIDATE ADAPTERS
    // =========================================================================

    /// <summary>
    /// Baseline candidate that uses the ground-truth settings with <see cref="EnigmaSimService"/>
    /// to verify that a 100% accurate solver achieves DSR = 1.0, CER = 0.0, State Accuracy = 1.0.
    /// </summary>
    private sealed class ReferenceOracleCandidate(
        string modelName,
        IReadOnlyList<GroundTruthCase> knownCases) : IEnigmaCrackCandidate
    {
        public string ModelName { get; } = modelName;

        public Task<CandidatePrediction> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(ciphertext);

            string sanitized = EvaluationMetricsCalculator.NormalizeAlphabet(ciphertext);
            if (sanitized.Length < 5)
            {
                throw new ArgumentException("Ciphertext is too short for cryptanalysis.", nameof(ciphertext));
            }

            GroundTruthCase? match = knownCases.FirstOrDefault(c => c.Ciphertext == sanitized);
            if (match is null)
            {
                return Task.FromResult(new CandidatePrediction(sanitized));
            }

            var sim = new EnigmaSimService();
            sim.Configure(match.Settings, RandomSettings: false);
            string decrypted = sim.Process(match.Ciphertext);

            return Task.FromResult(new CandidatePrediction(
                RecoveredPlaintext: decrypted,
                RecoveredSettings: match.Settings,
                RecoveredRotorOrder: match.EffectiveRotorOrder,
                RecoveredRingSettings: match.EffectiveRingSettings
            ));
        }
    }

    /// <summary>
    /// Simulates a realistic LLM cryptanalysis solver that succeeds on low-stecker messages
    /// and partially recovers rotor positions/plugboard on 10-stecker messages.
    /// </summary>
    private sealed class ImperfectSimulatedCandidate(
        string modelName,
        IReadOnlyList<GroundTruthCase> knownCases) : IEnigmaCrackCandidate
    {
        public string ModelName { get; } = modelName;

        public Task<CandidatePrediction> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(ciphertext);

            string sanitized = EvaluationMetricsCalculator.NormalizeAlphabet(ciphertext);
            if (sanitized.Length < 5)
            {
                throw new ArgumentException("Ciphertext is too short for cryptanalysis.", nameof(ciphertext));
            }

            GroundTruthCase? match = knownCases.FirstOrDefault(c => c.Ciphertext == sanitized);
            if (match is null)
            {
                return Task.FromResult(new CandidatePrediction(sanitized));
            }

            // Succeeds completely when plugboard has <= 2 pairs; partially recovers state when >= 5 pairs
            if (match.Settings.PlugboardPairs.Count <= 2)
            {
                return Task.FromResult(new CandidatePrediction(
                    RecoveredPlaintext: match.Plaintext,
                    RecoveredSettings: match.Settings,
                    RecoveredRotorOrder: match.EffectiveRotorOrder,
                    RecoveredRingSettings: match.EffectiveRingSettings
                ));
            }

            // Partial plugboard recovery: keep half of the stecker pairs, corrupt decryption accordingly
            var partialPlugboard = match.Settings.PlugboardPairs
                .Take(match.Settings.PlugboardPairs.Count / 2)
                .ToList();
            var partialSettings = match.Settings with { PlugboardPairs = partialPlugboard };

            var sim = new EnigmaSimService();
            sim.Configure(partialSettings, RandomSettings: false);
            string partiallyDecrypted = sim.Process(match.Ciphertext);

            return Task.FromResult(new CandidatePrediction(
                RecoveredPlaintext: partiallyDecrypted,
                RecoveredSettings: partialSettings,
                RecoveredRotorOrder: match.EffectiveRotorOrder,
                RecoveredRingSettings: match.EffectiveRingSettings
            ));
        }
    }
}
