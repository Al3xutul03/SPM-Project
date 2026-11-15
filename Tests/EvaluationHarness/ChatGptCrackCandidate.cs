using EnigmaLogic.Models.ChatGpt;
using EnigmaLogic.Services.Abstractions;

namespace Tests.EvaluationHarness;

/// <summary>
/// Adapter connecting <see cref="IEnigmaPredictChatGPTService"/> into the automated
/// <see cref="EnigmaBenchmarkRunner"/> evaluation harness.
/// </summary>
public sealed class ChatGptCrackCandidate(
    IEnigmaPredictChatGPTService service,
    EnigmaCrackOptions? options = null,
    string modelName = "ChatGPT") : IEnigmaCrackCandidate
{
    public string ModelName { get; } = modelName;

    public async Task<CandidatePrediction> CrackAsync(
        string ciphertext,
        CancellationToken cancellationToken = default)
    {
        EnigmaCrackResult result = await service
            .CrackAsync(ciphertext, options, cancellationToken)
            .ConfigureAwait(false);

        return new CandidatePrediction(
            RecoveredPlaintext: result.Plaintext,
            RecoveredSettings: result.Settings,
            RecoveredRotorOrder: (
                result.LeftRotor.ToString(),
                result.MiddleRotor.ToString(),
                result.RightRotor.ToString()
            ),
            RecoveredRingSettings: result.RingSettings
        );
    }
}
