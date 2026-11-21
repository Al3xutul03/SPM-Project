// EnigmaLogic/Services/EnigmaMachineDeepSeek.cs
using System;
using System.Collections.Generic;
using System.Text;

namespace EnigmaLogic.Services;

public static class EnigmaMachineDeepSeek
{
    public static readonly string[] RotorNames = { "I", "II", "III", "IV", "V" };

    // I   EKMFLGDQVZNTOWYHXUSPAIBRCJ
    // II  AJDKSIRUXBLHWTMCQGZNPYFVOE
    // III BDFHJLCPRTXVZNYEIWGAKMUSQO
    // IV  ESOVPZJAYQUIRHXLNFTGKDCMWB
    // V   VZBRGITYUPSDNHLXAWMJQOFECK
    public static readonly int[][] Forward =
    {
        new[]{4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9},
        new[]{0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4},
        new[]{1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14},
        new[]{4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1},
        new[]{21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10}
    };

    public static readonly int[][] Inverse = BuildInverse();
    public static readonly int[] Notch = { 16, 4, 21, 9, 25 };
    public static readonly int[] ReflectorB = { 24, 17, 20, 7, 16, 18, 11, 3, 15, 23, 13, 6, 14, 10, 12, 8, 4, 1, 5, 25, 2, 22, 21, 9, 0, 19 };
    public static readonly int[] ReflectorC = { 5, 21, 15, 9, 8, 0, 14, 24, 4, 3, 17, 25, 23, 22, 6, 2, 19, 10, 20, 16, 18, 1, 13, 12, 7, 11 };

    private static int[][] BuildInverse()
    {
        var inv = new int[5][];
        for (int r = 0; r < 5; r++)
        {
            inv[r] = new int[26];
            for (int i = 0; i < 26; i++) inv[r][Forward[r][i]] = i;
        }
        return inv;
    }

    public static string Sanitize(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            var c = char.ToUpperInvariant(ch);
            if (c >= 'A' && c <= 'Z') sb.Append(c);
        }
        return sb.ToString();
    }

    public static string Process(
        ReadOnlySpan<char> input, int[] rotors, int reflector,
        int posL, int posM, int posR,
        int ringL, int ringM, int ringR,
        int[] plug,
        out int finalPosL, out int finalPosM, out int finalPosR)
    {
        var sb = new StringBuilder(input.Length);
        int rL = rotors[0], rM = rotors[1], rR = rotors[2];
        int nL = Notch[rL], nM = Notch[rM], nR = Notch[rR];
        int[] refl = reflector == 0 ? ReflectorB : ReflectorC;
        int[] fL = Forward[rL], fM = Forward[rM], fR = Forward[rR];
        int[] iL = Inverse[rL], iM = Inverse[rM], iR = Inverse[rR];

        foreach (char raw in input)
        {
            if (raw < 'A' || raw > 'Z') continue;

            bool stepM = false, stepL = false;
            if (posM == nM) { stepM = true; stepL = true; }
            if (posR == nR) { stepM = true; }
            posR = (posR + 1) % 26;
            if (stepM) posM = (posM + 1) % 26;
            if (stepL) posL = (posL + 1) % 26;

            int offR = (posR - ringR + 26) % 26;
            int offM = (posM - ringM + 26) % 26;
            int offL = (posL - ringL + 26) % 26;

            int c = plug[raw - 'A'];
            c = Through(fR, c, offR);
            c = Through(fM, c, offM);
            c = Through(fL, c, offL);
            c = refl[c];
            c = Through(iL, c, offL);
            c = Through(iM, c, offM);
            c = Through(iR, c, offR);
            c = plug[c];
            sb.Append((char)('A' + c));
        }

        finalPosL = posL; finalPosM = posM; finalPosR = posR;
        return sb.ToString();
    }

    private static int Through(int[] wiring, int c, int offset)
    {
        int x = (c + offset) % 26;
        int y = wiring[x];
        return (y - offset + 26) % 26;
    }

    public static int RotorIndex(string name) => name.Trim().ToUpperInvariant() switch
    {
        "I" => 0,
        "II" => 1,
        "III" => 2,
        "IV" => 3,
        "V" => 4,
        _ => throw new ArgumentException($"Unknown rotor '{name}'.")
    };

    public static int ReflectorIndex(string name) => name.Trim().ToUpperInvariant() switch
    {
        "UKW-B" or "B" => 0,
        "UKW-C" or "C" => 1,
        _ => throw new ArgumentException($"Unknown reflector '{name}'.")
    };

    public static int[] BuildPlugboard(IReadOnlyList<string>? pairs)
    {
        var plug = new int[26];
        for (int i = 0; i < 26; i++) plug[i] = i;
        if (pairs == null) return plug;

        foreach (var raw in pairs)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var clean = Sanitize(raw);
            if (clean.Length != 2) continue;
            int a = clean[0] - 'A', b = clean[1] - 'A';
            if (a == b) continue;
            plug[a] = b; plug[b] = a;
        }
        return plug;
    }
}