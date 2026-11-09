namespace EnigmaLogic.Models;

/// <summary>
/// Simplified setup required before typing on the Enigma machine.
/// Uses standard rotors I, II, III (ring settings 'A') and Reflector B.
/// </summary>
/// <param name="Rotor1">Initial letter in the 1st (left) rotor window ('A'–'Z').</param>
/// <param name="Rotor2">Initial letter in the 2nd (middle) rotor window ('A'–'Z').</param>
/// <param name="Rotor3">Initial letter in the 3rd (right) rotor window ('A'–'Z').</param>
/// <param name="PlugboardPairs">Swapped letter pairs on the front panel (e.g., ["AB", "CD", "EF"]).</param>
public record EnigmaSettings(
    char Rotor1,
    char Rotor2,
    char Rotor3,
    IReadOnlyList<string> PlugboardPairs
);
