namespace EnigmaLogic.Models;

/// <summary>
/// Configuration for a single rotor slot in the Enigma machine.
/// </summary>
/// <param name="RotorName">Which physical rotor is used (e.g., "I", "II", "III", "IV", "V").</param>
/// <param name="RingSetting">Internal wiring offset (Ringstellung), 'A'–'Z'.</param>
/// <param name="InitialPosition">Starting letter in the window (Grundstellung), 'A'–'Z'.</param>
public record RotorConfig(
    string RotorName,
    char RingSetting,
    char InitialPosition
);
