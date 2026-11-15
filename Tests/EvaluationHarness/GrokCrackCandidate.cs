using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Cryptography;

namespace Tests.EvaluationHarness;

/// <summary>
/// Wraps the Grok-generated <see cref="EnigmaPredictGrokService"/> as an <see cref="IEnigmaCrackCandidate"/>:
/// cracks the ciphertext, then decrypts it with the reference <see cref="EnigmaSimService"/> using the recovered key.
/// The project machine is fixed (rotors I-II-III, rings AAA, reflector B), so those are reported as recovered.
/// </summary>
public sealed class GrokCrackCandidate : IEnigmaCrackCandidate
{
    private readonly EnigmaPredictGrokService _service = new();

    public string ModelName => "Grok";

    public static string SourceFilePath => Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..",
        "EnigmaLogic", "Services", "Cryptography", "EnigmaPredictGrokService.cs"));

    public async Task<CandidatePrediction> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        EnigmaSettings settings = await _service.CrackAsync(ciphertext, cancellationToken).ConfigureAwait(false);

        var machine = new EnigmaSimService();
        machine.Configure(settings, RandomSettings: false);

        return new CandidatePrediction(
            RecoveredPlaintext: machine.Process(ciphertext),
            RecoveredSettings: settings,
            RecoveredRotorOrder: ("I", "II", "III"),
            RecoveredRingSettings: ('A', 'A', 'A'));
    }
}