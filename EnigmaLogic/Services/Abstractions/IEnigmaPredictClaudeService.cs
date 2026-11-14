using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions;

public interface IEnigmaPredictClaudeService
{
    /// <summary>
    /// Rulează atacul de criptanaliză pe textul cifrat și returnează setările cele mai probabile.
    /// </summary>
    Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default);
}
