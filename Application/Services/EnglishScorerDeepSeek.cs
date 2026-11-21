// EnigmaLogic/Services/EnglishScorerDeepSeek.cs
using System;
using System.Collections.Generic;

namespace EnigmaLogic.Services;

public static class EnglishScorerDeepSeek
{
    private static readonly HashSet<int> Trigrams = BuildTrigrams();
    private static readonly HashSet<int> Quadgrams = BuildQuadgrams();

    private static readonly double[] ExpectedLetterFreq =
    {
        8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
        6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07
    };

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

    private static HashSet<int> BuildQuadgrams()
    {
        const string raw =
            "TION NTHE THER THAT OFTH FTHE WITH STHE ANDT OTHA NDTH HETH THET ATHE THEM HEST NTHA HERE OUND INTH ATIO " +
            "IGHT INGTIONS IONS ENTS HAVE THIS ALLY EVER ARTI FROM THEE INTE ONTH ATES OUGH THERETIONMENT PART WIT " +
            "TIVE ERTH ATIN OULD OUND ANCE ITHE ALLT OFTE SOME EART HICH LINE DOIN ONET MENT ASTH ONAL RIGH RECT " +
            "TATE ICTU ECTI TIES EVER ANDS TERS ESTH ONEW THES STHA LLTH TORE EACH THEI EARS ALLE INES ARES ANTH " +
            "OUGH THAN SEVE IOUS ONES MOST ENTE TING FULL THEH NCET HERS";

        var set = new HashSet<int>();
        foreach (var t in raw.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (t.Length != 4) continue;
            bool ok = true;
            foreach (char ch in t) if (ch < 'A' || ch > 'Z') { ok = false; break; }
            if (!ok) continue;
            set.Add((((t[0] - 'A') * 26 + (t[1] - 'A')) * 26 + (t[2] - 'A')) * 26 + (t[3] - 'A'));
        }
        return set;
    }

    public static double CoarseScore(string text)
    {
        if (text.Length < 2) return 0;

        var big = new int[26 * 26];
        int n = 0;
        int prev = -1;
        foreach (char ch in text)
        {
            int idx = ch - 'A';
            if ((uint)idx > 25) { prev = -1; continue; }
            if (prev >= 0) { big[prev * 26 + idx]++; n++; }
            prev = idx;
        }
        if (n == 0) return 0;

        double peak = 0;
        for (int a = 0; a < 26; a++)
        {
            int best = 0;
            int row = a * 26;
            for (int b = 0; b < 26; b++)
            {
                int c = big[row + b];
                if (c > best) best = c;
            }
            peak += best;
        }

        int distinct = 0;
        for (int i = 0; i < big.Length; i++) if (big[i] > 0) distinct++;

        return peak - 0.05 * distinct;
    }

    public static double Score(string text)
    {
        if (text.Length < 4) return CoarseScore(text);

        double trig = 0;
        for (int i = 0; i + 2 < text.Length; i++)
        {
            int a = text[i] - 'A', b = text[i + 1] - 'A', c = text[i + 2] - 'A';
            if ((uint)a > 25 || (uint)b > 25 || (uint)c > 25) continue;
            if (Trigrams.Contains((a * 26 + b) * 26 + c)) trig += 1;
        }

        double quad = 0;
        for (int i = 0; i + 3 < text.Length; i++)
        {
            int a = text[i] - 'A', b = text[i + 1] - 'A', c = text[i + 2] - 'A', d = text[i + 3] - 'A';
            if ((uint)a > 25 || (uint)b > 25 || (uint)c > 25 || (uint)d > 25) continue;
            if (Quadgrams.Contains((((a * 26 + b) * 26 + c) * 26) + d)) quad += 1;
        }

        var freq = new int[26];
        foreach (char ch in text) { int idx = ch - 'A'; if ((uint)idx <= 25) freq[idx]++; }

        int n = text.Length;
        double ioc = 0;
        for (int i = 0; i < 26; i++) ioc += freq[i] * (freq[i] - 1);
        if (n > 1) ioc /= (double)(n * (n - 1));

        double chi = 0;
        for (int i = 0; i < 26; i++)
        {
            double expected = n * ExpectedLetterFreq[i] / 100.0;
            if (expected < 1e-9) continue;
            double diff = freq[i] - expected;
            chi += diff * diff / expected;
        }

        return quad * 30.0 + trig * 4.0 + ioc * 600.0 - chi * 0.4;
    }
}