using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions
{
    /// <summary>
    /// Service responsible for recovering the most probable Enigma machine settings
    /// from a given ciphertext via heuristic cryptanalysis.
    /// </summary>
    public interface IEnigmaPredictGrokService
    {
        /// <summary>
        /// Rulează atacul de criptanaliză pe textul cifrat și returnează setările cele mai probabile.
        /// </summary>
        /// <param name="ciphertext">The encrypted text (A-Z letters expected).</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>
        /// The most probable <see cref="EnigmaSettings"/> recovered by the heuristic attack.
        /// </returns>
        Task<EnigmaSettings> CrackAsync(
            string ciphertext,
            CancellationToken cancellationToken = default);
    }
}