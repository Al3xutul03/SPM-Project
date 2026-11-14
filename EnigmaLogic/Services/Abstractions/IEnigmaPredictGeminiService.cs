using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions;

public interface IEnigmaPredictGeminiService
{
    /// Rulează atacul de criptanaliză pe textul cifrat și returnează setările cele mai probabile.
    Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default);
}