// FILE: EnigmaLogic/Services/EnglishScorerDeepSeek.cs
using System; using System.Collections.Generic;

namespace EnigmaLogic.Services;

public static class EnglishScorerDeepSeek
{
    private static readonly HashSet<int> Trigrams = BuildTrigrams();

    private static HashSet<int> BuildTrigrams()
    {
        const string raw =
        "THE AND ING HER HAT HIS THA ERE FOR ENT ION TER WAS YOU ITH VER ALL NTH HES ATI TIO OTH NTA INT STH ATE EAR " +
        "CON RES ONS NCE MAN PRO COM EST PER ECT IVE OUT AST ILL ANT PLA STO ART ORE EDT INE CHO RTI HEA STE IDE ICA " +
        "IGH ESS TIC WHI OME ENC ONE OUR ITI PLY ALS NOT BUT WHA SAI ARE HAV WIT THI UND WHE WIL EDI HEN ERV MEN LEA " +
        "MOR SOM TIM WEL TAK ONL EVE WAN LIK YEA LON GRE BEF MAK COU WOR AFT OVE SEM INC USE TWO FOU THO SUC END MAI " +
        "NEX OPE TWE";

        var set = new HashSet<int>();
        foreach (var t in raw.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (t.Length != 3) continue;
            if (t[0] < 'A' || t[0] > 'Z' || t[1] < 'A' || t[1] > 'Z' || t[2] < 'A' || t[2] > 'Z') continue;
            set.Add(((t[0] - 'A') * 26 + (t[1] - 'A')) * 26 + (t[2] - 'A'));
        }
        return set;
    }

    public static double Score(string text)
    {
        if (text.Length < 3) return 0;

        double trig = 0;
        for (int i = 0; i + 2 < text.Length; i++)
        {
            int a = text[i] - 'A';
            int b = text[i + 1] - 'A';
            int c = text[i + 2] - 'A';
            if ((uint)a > 25 || (uint)b > 25 || (uint)c > 25) continue;
            if (Trigrams.Contains((a * 26 + b) * 26 + c)) trig += 1;
        }

        var freq = new int[26];
        foreach (char ch in text) { int idx = ch - 'A'; if ((uint)idx <= 25) freq[idx]++; }

        int n = text.Length;
        double ioc = 0;
        if (n > 1)
        {
            for (int i = 0; i < 26; i++) ioc += freq[i] * (freq[i] - 1);
            ioc /= (double)(n * (n - 1));
        }

        return trig * 10.0 + ioc * 300.0;
    }
}