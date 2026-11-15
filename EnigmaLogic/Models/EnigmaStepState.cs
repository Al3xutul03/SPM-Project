namespace EnigmaLogic.Models;

/// <summary>
/// Obiect de stare utilizat pentru trasabilitate pas-cu-pas și animare în UI/View.
/// </summary>
/// <param name="RotorPositions">Rotor windows (Left, Middle, Right) after stepping for this keypress.</param>
/// <param name="InputChar">The key that was pressed.</param>
/// <param name="OutputChar">The lamp that lit up.</param>
public record EnigmaStepState(
    (char Left, char Middle, char Right) RotorPositions,
    char InputChar,
    char OutputChar
);
