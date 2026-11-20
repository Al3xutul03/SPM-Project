using EnigmaLogic.Models;
using EnigmaLogic.Services;

namespace Tests.EvaluationHarness;

/// <summary>
/// Evaluation of the Grok-generated cryptanalysis service with the shared evaluation harness:
/// correctness (DSR, CER, state reconstruction), efficiency (time, memory), code quality
/// (cyclomatic complexity) and robustness (edge cases, 5-run consistency).
/// </summary>
[TestClass]
public class GrokEvaluationTests
{
    // Generous bound for CI machines; locally a long message takes a few seconds.
    private static readonly TimeSpan MaxTimePerMessage = TimeSpan.FromSeconds(300);

    private static readonly Lazy<IReadOnlyList<GroundTruthCase>> LongMessages = new(CreateLongMessageSuite);

    public TestContext? TestContext { get; set; }

    // =========================================================================
    // 1. STANDARD HARNESS DATASET (17–98 letters)
    // =========================================================================

    [TestMethod]
    public async Task StandardBenchmark_SolvesFewPlugCasesAndReportsMetrics()
    {
        var runner = new EnigmaBenchmarkRunner();

        ModelEvaluationReport report = await runner.EvaluateCandidateAsync(new GrokCrackCandidate(), GrokCrackCandidate.SourceFilePath);
        WriteReport(report);

        Assert.AreEqual(5, report.TotalRuns);
        Assert.IsTrue(report.RunDetails.All(r => r.ErrorMessage is null),
            "Unexpected exceptions: " + string.Join("; ", report.RunDetails.Where(r => r.ErrorMessage is not null).Select(r => $"{r.CaseId}: {r.ErrorMessage}")));
        Assert.AreEqual(1.0, report.EdgeCasePassRate, 1e-9);

        foreach (string caseId in new[] { "GT-01-NoPlugboard-Short", "GT-02-TwoSteckers-Tactical" })
        {
            SingleRunMetrics run = report.RunDetails.Single(r => r.CaseId == caseId);
            Assert.IsTrue(run.IsExactMatch, $"{caseId} must decrypt exactly.");
            Assert.AreEqual(1.0, run.StateAccuracy.OverallStateAccuracy, 1e-9, $"{caseId} must recover the exact key.");
        }
    }

    // =========================================================================
    // 2. CORRECTNESS ON LONG MESSAGES (DSR, CER, State Reconstruction)
    // =========================================================================

    [TestMethod]
    public async Task LongMessages_AllDecryptedWithExactKey()
    {
        var runner = new EnigmaBenchmarkRunner(LongMessages.Value, edgeCases: []);

        ModelEvaluationReport report = await runner.EvaluateCandidateAsync(new GrokCrackCandidate());
        WriteReport(report);

        Assert.AreEqual(1.0, report.DecryptionSuccessRate, 1e-9, "Every long message must decrypt exactly.");
        Assert.AreEqual(0.0, report.AverageCharacterErrorRate, 1e-9);
        Assert.AreEqual(1.0, report.AverageStateReconstructionAccuracy, 1e-9);
        Assert.AreEqual(1.0, report.AverageStateBreakdown.PlugboardMappingAccuracy, 1e-9);
    }

    [TestMethod]
    [DataRow("EXT-01-German-NoPlugboard")]
    [DataRow("EXT-02-English-ThreeSteckers")]
    [DataRow("EXT-03-German-SixSteckers")]
    [DataRow("EXT-04-English-TenSteckers-Long")]
    [DataRow("EXT-05-German-TenSteckers-Short")]
    public async Task LongMessage_SingleCase_RecoversPositionsAndPlugboard(string caseId)
    {
        GroundTruthCase testCase = LongMessages.Value.Single(c => c.Id == caseId);

        SingleRunMetrics metrics = await EnigmaBenchmarkRunner.EvaluateSingleCaseAsync(new GrokCrackCandidate(), testCase);
        TestContext?.WriteLine($"{caseId}: {testCase.Ciphertext.Length} letters, {testCase.Settings.PlugboardPairs.Count} plugs, " +
            $"exact={metrics.IsExactMatch}, CER={metrics.CharacterErrorRate:P1}, t={metrics.ExecutionTime.TotalSeconds:F1}s");

        Assert.IsNull(metrics.ErrorMessage);
        Assert.IsTrue(metrics.IsExactMatch);
        Assert.AreEqual(1.0, metrics.StateAccuracy.RotorPositionAccuracy, 1e-9);
        Assert.AreEqual(1.0, metrics.StateAccuracy.PlugboardPairAccuracy, 1e-9);
    }

    // =========================================================================
    // 3. EFFICIENCY (EffiBench)
    // =========================================================================

    [TestMethod]
    public async Task Efficiency_LongestTenPlugMessage_StaysWithinTimeBound()
    {
        GroundTruthCase testCase = LongMessages.Value.Single(c => c.Id == "EXT-04-English-TenSteckers-Long");

        SingleRunMetrics metrics = await EnigmaBenchmarkRunner.EvaluateSingleCaseAsync(new GrokCrackCandidate(), testCase);
        TestContext?.WriteLine($"Time={metrics.ExecutionTime.TotalSeconds:F2}s, Allocated={metrics.AllocatedBytes / 1024.0 / 1024.0:F1} MB, " +
            $"WorkingSetDelta={metrics.PeakWorkingSetDeltaBytes / 1024.0 / 1024.0:F1} MB");

        Assert.IsTrue(metrics.IsExactMatch);
        Assert.IsLessThanOrEqualTo(MaxTimePerMessage, metrics.ExecutionTime);
    }

    // =========================================================================
    // 4. CODE QUALITY (McCabe Cyclomatic Complexity)
    // =========================================================================

    [TestMethod]
    public void CyclomaticComplexity_GrokServiceSource_AverageWithinMcCabeBound()
    {
        Assert.IsTrue(File.Exists(GrokCrackCandidate.SourceFilePath), $"Could not locate {GrokCrackCandidate.SourceFilePath}");

        FileComplexityReport report = CyclomaticComplexityAnalyzer.AnalyzeFile(GrokCrackCandidate.SourceFilePath);
        TestContext?.WriteLine($"Methods: {report.MethodCount} | Avg CC: {report.AverageCyclomaticComplexity:F2} | " +
            $"Max CC: {report.MaxCyclomaticComplexity} | Above {CyclomaticComplexityAnalyzer.McCabeRecommendedUpperBound}: {report.MethodsExceedingThreshold}");
        foreach (MethodComplexityMetric method in report.Methods.Where(m => m.ExceedsMcCabeThreshold))
            TestContext?.WriteLine($"  CC {method.CyclomaticComplexity}: {method.MethodSignature}");

        Assert.IsGreaterThan(0, report.MethodCount);
        Assert.IsLessThanOrEqualTo(CyclomaticComplexityAnalyzer.McCabeRecommendedUpperBound, report.AverageCyclomaticComplexity);
    }

    // =========================================================================
    // 5. ROBUSTNESS (Edge cases, 5-run consistency)
    // =========================================================================

    [TestMethod]
    public async Task Robustness_EdgeCases_AllHandledGracefully()
    {
        var runner = new EnigmaBenchmarkRunner(groundTruthSuite: []);

        double passRate = await runner.EvaluateEdgeCaseRobustnessAsync(new GrokCrackCandidate());

        Assert.AreEqual(1.0, passRate, 1e-9);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("   \t\r\n  ")]
    [DataRow("A")]
    [DataRow("1234567890!@#$%^&*()")]
    public async Task Robustness_InputWithoutEnoughLetters_ThrowsArgumentException(string input)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => new GrokCrackCandidate().CrackAsync(input));
    }

    [TestMethod]
    public async Task Robustness_LowerCaseAndSymbols_SameResultAsCleanCiphertext()
    {
        GroundTruthCase testCase = LongMessages.Value.Single(c => c.Id == "EXT-02-English-ThreeSteckers");
        string noisy = string.Join(" ", testCase.Ciphertext.ToLowerInvariant().Chunk(5).Select(group => new string(group))) + " !?";

        CandidatePrediction prediction = await new GrokCrackCandidate().CrackAsync(noisy);

        Assert.IsTrue(EvaluationMetricsCalculator.IsExactPlaintextMatch(testCase.Plaintext, prediction.RecoveredPlaintext));
    }

    [TestMethod]
    public async Task Robustness_CancelledToken_ThrowsOperationCanceledException()
    {
        GroundTruthCase testCase = LongMessages.Value.Single(c => c.Id == "EXT-04-English-TenSteckers-Long");
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAsync<OperationCanceledException>(() => new GrokCrackCandidate().CrackAsync(testCase.Ciphertext, cts.Token));
    }

    [TestMethod]
    public async Task Robustness_FiveRunConsistency_IdenticalResults()
    {
        GroundTruthCase[] cases = LongMessages.Value
            .Where(c => c.Id is "EXT-02-English-ThreeSteckers" or "EXT-05-German-TenSteckers-Short")
            .ToArray();
        var runner = new EnigmaBenchmarkRunner(cases, edgeCases: []);
        var dsrPerRun = new List<double>();
        var keysPerRun = new List<string>();

        for (int run = 0; run < 5; run++)
        {
            ModelEvaluationReport report = await runner.EvaluateCandidateAsync(new GrokCrackCandidate());
            dsrPerRun.Add(report.DecryptionSuccessRate);
        }

        foreach (GroundTruthCase testCase in cases)
        {
            for (int run = 0; run < 2; run++)
            {
                CandidatePrediction prediction = await new GrokCrackCandidate().CrackAsync(testCase.Ciphertext);
                keysPerRun.Add($"{testCase.Id}:{Describe(prediction.RecoveredSettings!)}");
            }
        }

        var (meanDsr, stdDev, consistency) = EvaluationMetricsCalculator.CalculateMultiRunConsistency(dsrPerRun);
        TestContext?.WriteLine($"5-run DSR: [{string.Join(", ", dsrPerRun)}], mean={meanDsr:F2}, sd={stdDev:F3}, consistency={consistency:F3}");

        Assert.AreEqual(1.0, meanDsr, 1e-9);
        Assert.AreEqual(1.0, consistency, 1e-9);
        Assert.AreEqual(cases.Length, keysPerRun.Distinct().Count(), "The same ciphertext must always yield the same key.");
    }

    // =========================================================================
    // DATASET AND HELPERS
    // =========================================================================

    private static IReadOnlyList<GroundTruthCase> CreateLongMessageSuite()
    {
        const string germanReport =
            "Am fruehen Morgen erreichte die Spaehgruppe das verlassene Gehoeft am Waldrand und meldete keine Bewegung " +
            "auf der Landstrasse. Die Pioniere begannen sofort mit dem Bau einer Behelfsbruecke ueber den Bach, weil die " +
            "alte Steinbruecke in der Nacht eingestuerzt war. Gegen Mittag trafen zwei Lastwagen mit Verpflegung und " +
            "Decken ein. Der Hauptmann verlangt bis zum Abend einen Bericht ueber den Zustand der Wege nach Osten sowie " +
            "eine Liste aller Verwundeten. Die Funkverbindung zur Nachbarkompanie bleibt schwach, deshalb werden " +
            "Meldungen bis auf weiteres durch Melder auf Kraedern ueberbracht.";

        const string englishLetter =
            "Dear Margaret, the harvest came in a week early this year, and the barn is so full that we had to stack the " +
            "last bales under a canvas behind the stables. Your brother repaired the old windmill on Sunday, although it " +
            "still groans whenever the wind turns to the north. The village has decided to hold the autumn fair on the " +
            "green again, with music, a baking contest and a race for the children along the river path. Father insists " +
            "that you bring the blue umbrella back when you visit, because he claims it is the only one that has never " +
            "turned inside out. We all miss you and hope the city is treating you kindly. Write soon and tell us about " +
            "the new library, the trams and the people you have met at the observatory.";

        var specs = new (string Id, string Plaintext, EnigmaSettings Settings)[]
        {
            ("EXT-01-German-NoPlugboard", germanReport,
                new EnigmaSettings('B', 'Q', 'R', [])),
            ("EXT-02-English-ThreeSteckers", englishLetter[..380],
                new EnigmaSettings('M', 'O', 'H', ["AI", "ES", "HX"])),
            ("EXT-03-German-SixSteckers", germanReport,
                new EnigmaSettings('Z', 'R', 'U', ["BT", "CK", "DN", "FW", "GL", "PY"])),
            ("EXT-04-English-TenSteckers-Long", englishLetter,
                new EnigmaSettings('K', 'D', 'T', ["AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"])),
            ("EXT-05-German-TenSteckers-Short", germanReport[..300],
                new EnigmaSettings('M', 'C', 'K', ["AZ", "BX", "CW", "DV", "EU", "FT", "GS", "HR", "IQ", "JP"])),
        };

        var sim = new EnigmaSimService();
        return specs.Select(spec =>
        {
            sim.Configure(spec.Settings, RandomSettings: false);
            string ciphertext = sim.Process(spec.Plaintext);
            return new GroundTruthCase(spec.Id, sim.LastInput!, ciphertext, spec.Settings, ("I", "II", "III"), ('A', 'A', 'A'));
        }).ToArray();
    }

    private static string Describe(EnigmaSettings settings) =>
        $"{settings.Rotor1}{settings.Rotor2}{settings.Rotor3} {string.Join(' ', settings.PlugboardPairs.Order())}";

    private void WriteReport(ModelEvaluationReport report)
    {
        TestContext?.WriteLine(
            $"[{report.ModelName}] DSR={report.DecryptionSuccessRate:P1} ({report.SuccessfulRuns}/{report.TotalRuns}), " +
            $"CER={report.AverageCharacterErrorRate:P1}, StateAcc={report.AverageStateReconstructionAccuracy:P1}, " +
            $"AvgTime={report.AverageExecutionTime.TotalSeconds:F2}s, MaxTime={report.MaxExecutionTime.TotalSeconds:F2}s, " +
            $"AvgAlloc={report.AverageAllocatedBytes / 1024.0 / 1024.0:F1} MB, EdgePass={report.EdgeCasePassRate:P0}, " +
            $"AvgCC={report.AverageCyclomaticComplexity:F2}, MaxCC={report.MaxCyclomaticComplexity}");

        foreach (SingleRunMetrics run in report.RunDetails)
        {
            TestContext?.WriteLine(
                $"  {run.CaseId}: exact={run.IsExactMatch}, CER={run.CharacterErrorRate:P1}, " +
                $"positions={run.StateAccuracy.RotorPositionAccuracy:P0}, plugs={run.StateAccuracy.PlugboardPairAccuracy:P0}, " +
                $"t={run.ExecutionTime.TotalSeconds:F2}s{(run.ErrorMessage is null ? "" : ", error=" + run.ErrorMessage)}");
        }
    }
}