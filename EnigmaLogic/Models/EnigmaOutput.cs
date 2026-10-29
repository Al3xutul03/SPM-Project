namespace EnigmaLogic.Models;

/// <summary>
/// The output produced by the Enigma machine after processing text.
/// </summary>
/// <param name="OutputText">The resulting encrypted or decrypted A–Z string.</param>
/// <param name="FinalRotorPositions">Where the 3 rotor windows ended up after typing (Left, Middle, Right).</param>
public record EnigmaOutput(
    string OutputText,
    (char Left, char Middle, char Right) FinalRotorPositions
);
