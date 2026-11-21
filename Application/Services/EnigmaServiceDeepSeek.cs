// EnigmaLogic/Services/EnigmaServiceDeepSeek.cs
using System;
using System.Collections.Generic;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services;

public sealed class EnigmaServiceDeepSeek : IEnigmaServiceDeepSeek
{
    private int[] _rotors = { 0, 1, 2 };
    private int _reflector = 0;
    private int _posL, _posM, _posR;
    private int _ringL, _ringM, _ringR;
    private int[] _plug = Identity();

    private static int[] Identity() { var a = new int[26]; for (int i = 0; i < 26; i++) a[i] = i; return a; }

    public void Configure(EnigmaSettingsDeepSeek? settings = null, bool RandomSettings = true)
    {
        if (RandomSettings || settings is null)
        {
            var rnd = new Random();
            var pool = new List<int> { 0, 1, 2, 3, 4 };
            int Pick() { int i = rnd.Next(pool.Count); int v = pool[i]; pool.RemoveAt(i); return v; }

            _rotors = new[] { Pick(), Pick(), Pick() };
            _reflector = rnd.Next(2);
            _ringL = rnd.Next(26); _ringM = rnd.Next(26); _ringR = rnd.Next(26);
            _posL = rnd.Next(26); _posM = rnd.Next(26); _posR = rnd.Next(26);
            _plug = Identity();
            return;
        }

        _rotors = new[]
        {
            EnigmaMachineDeepSeek.RotorIndex(settings.LeftRotor.RotorName),
            EnigmaMachineDeepSeek.RotorIndex(settings.MiddleRotor.RotorName),
            EnigmaMachineDeepSeek.RotorIndex(settings.RightRotor.RotorName)
        };
        _reflector = EnigmaMachineDeepSeek.ReflectorIndex(settings.Reflector);

        _ringL = Norm(settings.LeftRotor.RingSetting);
        _ringM = Norm(settings.MiddleRotor.RingSetting);
        _ringR = Norm(settings.RightRotor.RingSetting);

        _posL = Norm(settings.LeftRotor.InitialPosition);
        _posM = Norm(settings.MiddleRotor.InitialPosition);
        _posR = Norm(settings.RightRotor.InitialPosition);

        _plug = EnigmaMachineDeepSeek.BuildPlugboard(settings.PlugboardPairs);
    }

    private static int Norm(char ch)
    {
        char c = char.ToUpperInvariant(ch);
        if (c < 'A' || c > 'Z') throw new ArgumentException($"Invalid letter '{ch}'.");
        return c - 'A';
    }

    public EnigmaOutputDeepSeek Process(string inputText)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(inputText);
        var output = EnigmaMachineDeepSeek.Process(
            clean.AsSpan(), _rotors, _reflector,
            _posL, _posM, _posR, _ringL, _ringM, _ringR, _plug,
            out int fL, out int fM, out int fR);

        var finalPositions = (
            Left: (char)('A' + fL),
            Middle: (char)('A' + fM),
            Right: (char)('A' + fR));

        return new EnigmaOutputDeepSeek(output, finalPositions);
    }
}