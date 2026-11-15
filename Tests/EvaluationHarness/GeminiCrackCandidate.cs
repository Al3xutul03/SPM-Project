using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Abstractions;

namespace Tests.EvaluationHarness;

/// <summary>
/// Adapter connecting <see cref="IEnigmaPredictGeminiService"/> into the automated
/// <see cref="EnigmaBenchmarkRunner"/> evaluation harness.
/// </summary>
public sealed class GeminiCrackCandidate(
    IEnigmaPredictGeminiService service,
    string modelName = "Gemini-AsGenerated") : IEnigmaCrackCandidate
{
    public string ModelName { get; } = modelName;

    public async Task<CandidatePrediction> CrackAsync(
        string ciphertext,
        CancellationToken cancellationToken = default)
    {
        EnigmaSettings settings = await service
            .CrackAsync(ciphertext, cancellationToken)
            .ConfigureAwait(false);

        // Decrypt using reference simulator to extract recovered plaintext
        var decryptor = new EnigmaSimService();
        decryptor.Configure(settings, RandomSettings: false);
        string plaintext = decryptor.Process(ciphertext);

        return new CandidatePrediction(
            RecoveredPlaintext: plaintext,
            RecoveredSettings: settings,
            RecoveredRotorOrder: ("I", "II", "III"),
            RecoveredRingSettings: ('A', 'A', 'A')
        );
    }
}
