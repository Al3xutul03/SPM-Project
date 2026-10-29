namespace EnigmaLogic.Models;

/// <summary>
/// Complete setup required before typing on the Enigma machine.
/// </summary>
/// <param name="LeftRotor">Slowest-moving rotor (left slot).</param>
/// <param name="MiddleRotor">Middle-slot rotor.</param>
/// <param name="RightRotor">Fastest-moving rotor (right slot, steps on every keypress).</param>
/// <param name="Reflector">Reflector type (e.g., "B" or "C").</param>
/// <param name="PlugboardPairs">Swapped letter pairs on the front panel (e.g., ["AB", "CD", "EF"]).</param>
public record EnigmaSettings(
    RotorConfig LeftRotor,
    RotorConfig MiddleRotor,
    RotorConfig RightRotor,
    string Reflector,
    IReadOnlyList<string> PlugboardPairs
);
