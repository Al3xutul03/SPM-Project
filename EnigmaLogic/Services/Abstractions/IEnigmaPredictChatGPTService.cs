using EnigmaLogic.Models;
using EnigmaLogic.Models.ChatGpt;

namespace EnigmaLogic.Services.Abstractions;

/// <summary>
/// Provides Enigma I / M3 cryptanalysis and statistical analysis.
/// </summary>
public interface IEnigmaPredictChatGPTService
{
    /// <summary>
    /// Attempts to recover plaintext and machine settings.
    /// </summary>
    Task<EnigmaCrackResult> CrackAsync(
        string ciphertext,
        EnigmaCrackOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Processes text using a specified Enigma configuration.
    /// </summary>
    EnigmaOutput Simulate(
        string input,
        EnigmaSettings settings,
        EnigmaRotor leftRotor = EnigmaRotor.I,
        EnigmaRotor middleRotor = EnigmaRotor.II,
        EnigmaRotor rightRotor = EnigmaRotor.III,
        EnigmaReflector reflector = EnigmaReflector.B,
        (char Left, char Middle, char Right)? ringSettings = null);

    /// <summary>
    /// Calculates the Index of Coincidence.
    /// </summary>
    double CalculateIndexOfCoincidence(string text);

    /// <summary>
    /// Calculates n-gram fitness.
    /// </summary>
    double CalculateFitness(string text, EnigmaNGramModel model);

    /// <summary>
    /// Calculates a combined statistical analysis.
    /// </summary>
    EnigmaTextAnalysis AnalyzeText(
        string text,
        EnigmaNGramModel? model = null);
}