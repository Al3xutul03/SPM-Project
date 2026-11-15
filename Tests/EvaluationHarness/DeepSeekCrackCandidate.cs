using EnigmaLogic.Models;
using EnigmaLogic.Services;

namespace Tests.EvaluationHarness;

/// <summary>
/// Wraps the DeepSeek-generated <see cref="EnigmaPredictServiceDeepSeek"/> as an <see cref="IEnigmaCrackCandidate"/>:
/// cracks the ciphertext, then decrypts it with DeepSeek's own <see cref="EnigmaServiceDeepSeek"/> using the recovered key.
/// DeepSeek searches all five rotors and both reflectors, so the recovered rotor order and ring settings are reported
/// as found (not assumed to be I-II-III / AAA), and the harness scores them against the project machine.
/// </summary>
public sealed class DeepSeekCrackCandidate : IEnigmaCrackCandidate
{
    private readonly EnigmaPredictServiceDeepSeek _service = new();

    public string ModelName => "DeepSeek";

    public static string SourceFilePath => Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..",
        "Application", "Services", "EnigmaPredictServiceDeepSeek.cs"));

    public async Task<CandidatePrediction> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        EnigmaSettingsDeepSeek found = await _service.CrackAsync(ciphertext, cancellationToken).ConfigureAwait(false);

        var machine = new EnigmaServiceDeepSeek();
        machine.Configure(found, RandomSettings: false);

        return new CandidatePrediction(
            RecoveredPlaintext: machine.Process(ciphertext).OutputText,
            RecoveredSettings: ToProjectSettings(found),
            RecoveredRotorOrder: (found.LeftRotor.RotorName, found.MiddleRotor.RotorName, found.RightRotor.RotorName),
            RecoveredRingSettings: (found.LeftRotor.RingSetting, found.MiddleRotor.RingSetting, found.RightRotor.RingSetting));
    }

    /// <summary>Starting positions and plugboard of a DeepSeek key, in the project's <see cref="EnigmaSettings"/> shape.</summary>
    public static EnigmaSettings ToProjectSettings(EnigmaSettingsDeepSeek settings) =>
        new(settings.LeftRotor.InitialPosition,
            settings.MiddleRotor.InitialPosition,
            settings.RightRotor.InitialPosition,
            settings.PlugboardPairs);

    /// <summary>The project machine (rotors I-II-III, rings AAA, reflector B) expressed as a DeepSeek key.</summary>
    public static EnigmaSettingsDeepSeek FromProjectSettings(EnigmaSettings settings) =>
        new(new RotorConfigDeepSeek("I", 'A', settings.Rotor1),
            new RotorConfigDeepSeek("II", 'A', settings.Rotor2),
            new RotorConfigDeepSeek("III", 'A', settings.Rotor3),
            "UKW-B",
            settings.PlugboardPairs);
}