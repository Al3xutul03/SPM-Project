// FILE: EnigmaLogic/Models/EnigmaModelsDeepSeek.cs
using System.Collections.Generic;

namespace EnigmaLogic.Models
{
    public record RotorConfigDeepSeek(
    string RotorName,
    char RingSetting,
    char InitialPosition);

    public record EnigmaSettingsDeepSeek(
    RotorConfigDeepSeek LeftRotor,
    RotorConfigDeepSeek MiddleRotor,
    RotorConfigDeepSeek RightRotor,
    string Reflector,
    IReadOnlyList<string> PlugboardPairs);

    public record EnigmaOutputDeepSeek(
    string OutputText,
    (char Left, char Middle, char Right) FinalRotorPositions);

    public record EnigmaStepStateDeepSeek(
    (char Left, char Middle, char Right) RotorPositions,
    char InputChar,
    char OutputChar);
}