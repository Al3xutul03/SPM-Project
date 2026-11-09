using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions;

public interface IEnigmaSimService
{
    /// <summary>
    /// Sets the rotors, ring settings, initial positions, reflector, and plugboard.
    /// </summary>
    /// <param name="settings">The complete machine setup configuration.</param>
    /// <param name="RandomSettings">If true, randomizes the settings instead of using the provided configuration.</param>
    void Configure(EnigmaSettings? settings = null, bool RandomSettings = true);

    /// <summary>
    /// Runs input text through the configured machine.
    /// along with the updated rotor window positions.
    /// </summary>
    /// <returns>The processed text.</returns>
    string Process();

    /// <summary>
    /// Checks if the guessed input and guessed initial machine settings match the actual simulation state.
    /// </summary>
    /// <param name="expectedInput">The plaintext input that is guessed.</param>
    /// <param name="expectedSettings">The initial machine configuration that is guessed.</param>
    /// <returns>True if both the input and initial machine settings are correct, false otherwise.</returns>
    bool IsCorrect(string expectedInput, EnigmaSettings expectedSettings);
}
