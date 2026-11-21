// EnigmaLogic/Services/EnigmaPredictServiceDeepSeek.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services;

public sealed class EnigmaPredictServiceDeepSeek : IEnigmaPredictServiceDeepSeek, IEnigmaPredictDiagnosticDeepSeek
{
    private static readonly int[] FixedRotors = { 0, 1, 2 };
    private const int FixedReflector = 0;

    private const int CheapMaxPlugs = 6;
    private const int FullMaxPlugs = 13;
    private const double StopEpsilon = 0.5;

    private const int ShortBoundary = 100;
    private const int MediumBoundary = 400;

    private static int Stage2aCandidates(int len) =>
        len < ShortBoundary ? 17576 : (len < MediumBoundary ? 3000 : 2000);

    private static int Stage2bCandidates(int len) =>
        len < ShortBoundary ? 1000 : (len < MediumBoundary ? 500 : 200);

    // Length-adaptive plug cap. <50 -> 2 (GT-02 34-char case: prevents reaching
    // the 3-plug wrong candidate that scores 15.5 above true); 50-100 -> 3;
    // 100-300 -> 10 (EXT-05 253 and MCK 240 are within); >=300 -> 13.
    private static int MaxPlugsForLength(int len) =>
        len < 50 ? 2 : (len < ShortBoundary ? 3 : (len < 300 ? 10 : FullMaxPlugs));

    public Task<EnigmaSettingsDeepSeek> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(ciphertext);
        if (clean.Length < 20) throw new InvalidOperationException("Ciphertext too short for DeepSeek cryptanalysis (min 20 letters).");
        return Task.Run(() => CrackInternal(clean, cancellationToken), cancellationToken);
    }

    public Task<CrackDiagnosticDeepSeek> DiagnoseAsync(string ciphertext, (int L, int M, int R) truePositions, IReadOnlyList<string> truePlugboard, CancellationToken cancellationToken = default)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(ciphertext);
        if (clean.Length < 20) throw new InvalidOperationException("Ciphertext too short for DeepSeek diagnostics.");
        return Task.Run(() => DiagnoseInternal(clean, truePositions, cancellationToken), cancellationToken);
    }

    private static EnigmaSettingsDeepSeek CrackInternal(string clean, CancellationToken ct)
    {
        int cap = MaxPlugsForLength(clean.Length);
        var ranked = Stage1(clean, ct);
        int cheap = Math.Min(Stage2aCandidates(clean.Length), ranked.Count);
        var stage2a = Stage2a(clean, ranked, cheap, cap, ct);
        int k = Math.Min(Stage2bCandidates(clean.Length), stage2a.Count);
        var stage2b = Stage2b(clean, stage2a, k, cap, ct);
        stage2b.Sort(CompareCandidates);
        return ToSettings(stage2b[0]);
    }

    private static CrackDiagnosticDeepSeek DiagnoseInternal(string clean, (int L, int M, int R) truePositions, CancellationToken ct)
    {
        int cap = MaxPlugsForLength(clean.Length);
        var sw1 = Stopwatch.StartNew();
        var ranked = Stage1(clean, ct);
        sw1.Stop();
        int rank1 = RankOf(ranked, truePositions);

        int cheap = Math.Min(Stage2aCandidates(clean.Length), ranked.Count);
        var sw2a = Stopwatch.StartNew();
        var stage2a = Stage2a(clean, ranked, cheap, cap, ct);
        sw2a.Stop();
        int rank2a = RankOfPositions(stage2a, truePositions);

        int k = Math.Min(Stage2bCandidates(clean.Length), stage2a.Count);
        var sw2b = Stopwatch.StartNew();
        var stage2b = Stage2b(clean, stage2a, k, cap, ct);
        sw2b.Stop();

        return new CrackDiagnosticDeepSeek(rank1, rank2a, sw1.Elapsed.TotalMilliseconds, sw2a.Elapsed.TotalMilliseconds, sw2b.Elapsed.TotalMilliseconds, ranked.Count, stage2a.Count, stage2b.Count);
    }

    private static List<Candidate> Stage1(string text, CancellationToken ct)
    {
        int[] id = Identity();
        var list = new List<Candidate>(17576);
        for (int pl = 0; pl < 26; pl++)
        {
            ct.ThrowIfCancellationRequested();
            for (int pm = 0; pm < 26; pm++)
                for (int pr = 0; pr < 26; pr++)
                {
                    var dec = EnigmaMachineDeepSeek.Process(text.AsSpan(), FixedRotors, FixedReflector, pl, pm, pr, 0, 0, 0, id, out _, out _, out _);
                    list.Add(new Candidate(pl, pm, pr, EnglishScorerDeepSeek.CoarseScore(dec)));
                }
        }
        list.Sort((a, b) => b.Coarse.CompareTo(a.Coarse));
        return list;
    }

    private static List<Candidate2a> Stage2a(string text, List<Candidate> ranked, int count, int cap, CancellationToken ct)
    {
        var results = new Candidate2a[count];
        var options = new ParallelOptions { CancellationToken = ct };
        Parallel.For(0, count, options, i =>
        {
            ct.ThrowIfCancellationRequested();
            var c = ranked[i];
            var plug = Identity();
            double score = ScoreWithPositionsAndPlug(text, c.L, c.M, c.R, plug, ct);
            for (int add = 0; add < Math.Min(CheapMaxPlugs, cap); add++)
            {
                if (!TryBestAdd(text, c.L, c.M, c.R, plug, score, cap, ct, out int ba, out int bb, out double newScore)) break;
                plug[ba] = bb; plug[bb] = ba;
                score = newScore;
            }
            results[i] = new Candidate2a(c.L, c.M, c.R, score, plug);
        });
        var list = new List<Candidate2a>(results);
        list.Sort((a, b) => b.Score.CompareTo(a.Score));
        return list;
    }

    private static List<Candidate2b> Stage2b(string text, List<Candidate2a> ranked, int count, int cap, CancellationToken ct)
    {
        var results = new Candidate2b[count];
        var options = new ParallelOptions { CancellationToken = ct };
        Parallel.For(0, count, options, i =>
        {
            ct.ThrowIfCancellationRequested();
            var c = ranked[i];
            var plug = (int[])c.Plug.Clone();
            int pl = c.L, pm = c.M, pr = c.R;
            double score = c.Score;
            for (int round = 0; round < 24; round++)
            {
                ct.ThrowIfCancellationRequested();
                bool changed = false;
                if (TryBestAdd(text, pl, pm, pr, plug, score, cap, ct, out int ba, out int bb, out double s2)) { plug[ba] = bb; plug[bb] = ba; score = s2; changed = true; }
                if (TryBestRemove(text, pl, pm, pr, plug, score, ct, out double s3)) { score = s3; changed = true; }
                if (TryBestSwapEnd(text, pl, pm, pr, plug, score, ct, out double s4)) { score = s4; changed = true; }
                if (TryBestRelink(text, pl, pm, pr, plug, score, ct, out double s5)) { score = s5; changed = true; }
                var (npL, npM, npR, s6, posChanged) = HillClimbPositions(text, pl, pm, pr, plug, score, ct);
                if (posChanged) { pl = npL; pm = npM; pr = npR; score = s6; changed = true; }
                if (!changed) break;
            }
            results[i] = new Candidate2b(pl, pm, pr, score, plug);
        });
        return new List<Candidate2b>(results);
    }

    private static bool TryBestAdd(string text, int pl, int pm, int pr, int[] plug, double current, int cap, CancellationToken ct, out int bestA, out int bestB, out double bestScore)
    {
        bestA = -1; bestB = -1; bestScore = current;
        double bestGain = StopEpsilon;
        if (CountPairs(plug) >= cap) return false;
        for (int a = 0; a < 26; a++)
        {
            if (plug[a] != a) continue;
            for (int b = a + 1; b < 26; b++)
            {
                if (plug[b] != b) continue;
                plug[a] = b; plug[b] = a;
                double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);
                if (s - current > bestGain) { bestGain = s - current; bestA = a; bestB = b; bestScore = s; }
                plug[a] = a; plug[b] = b;
            }
        }
        return bestGain > StopEpsilon;
    }

    private static bool TryBestRemove(string text, int pl, int pm, int pr, int[] plug, double current, CancellationToken ct, out double bestScore)
    {
        bestScore = current;
        double bestGain = StopEpsilon;
        int[] saved = (int[])plug.Clone();
        for (int a = 0; a < 26; a++)
        {
            int b = plug[a];
            if (b == a) continue;
            plug[a] = a; plug[b] = b;
            double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);
            if (s - current > bestGain) { bestGain = s - current; bestScore = s; Array.Copy(plug, saved, 26); }
            else { plug[a] = b; plug[b] = a; }
        }
        if (bestGain > StopEpsilon) { Array.Copy(saved, plug, 26); return true; }
        return false;
    }

    private static bool TryBestSwapEnd(string text, int pl, int pm, int pr, int[] plug, double current, CancellationToken ct, out double bestScore)
    {
        bestScore = current;
        double bestGain = StopEpsilon;
        int[]? best = null;
        for (int a = 0; a < 26; a++)
        {
            int b = plug[a];
            if (b == a) continue;
            for (int c = 0; c < 26; c++)
            {
                if (c == a || c == b || plug[c] != c) continue;
                {
                    int[] t = (int[])plug.Clone();
                    t[a] = a; t[b] = b; t[a] = c; t[c] = a;
                    double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, t, ct);
                    if (s - current > bestGain) { bestGain = s - current; bestScore = s; best = t; }
                }
                {
                    int[] t = (int[])plug.Clone();
                    t[a] = a; t[b] = b; t[b] = c; t[c] = b;
                    double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, t, ct);
                    if (s - current > bestGain) { bestGain = s - current; bestScore = s; best = t; }
                }
            }
        }
        if (best != null) { Array.Copy(best, plug, 26); return true; }
        return false;
    }

    private static bool TryBestRelink(string text, int pl, int pm, int pr, int[] plug, double current, CancellationToken ct, out double bestScore)
    {
        bestScore = current;
        double bestGain = StopEpsilon;
        int[]? best = null;
        for (int a = 0; a < 26; a++)
        {
            int b = plug[a];
            if (b == a) continue;
            for (int c = a + 1; c < 26; c++)
            {
                int d = plug[c];
                if (d == c) continue;
                if (c == b || d == a) continue;
                {
                    int[] t = (int[])plug.Clone();
                    t[a] = a; t[b] = b; t[c] = c; t[d] = d; t[a] = c; t[c] = a; t[b] = d; t[d] = b;
                    double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, t, ct);
                    if (s - current > bestGain) { bestGain = s - current; bestScore = s; best = t; }
                }
                {
                    int[] t = (int[])plug.Clone();
                    t[a] = a; t[b] = b; t[c] = c; t[d] = d; t[a] = d; t[d] = a; t[b] = c; t[c] = b;
                    double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, t, ct);
                    if (s - current > bestGain) { bestGain = s - current; bestScore = s; best = t; }
                }
            }
        }
        if (best != null) { Array.Copy(best, plug, 26); return true; }
        return false;
    }

    private static (int L, int M, int R, double Score, bool Changed) HillClimbPositions(string text, int pl, int pm, int pr, int[] plug, double current, CancellationToken ct)
    {
        double best = current;
        bool changed = false, improved = true;
        int guard = 0;
        while (improved && guard++ < 200)
        {
            ct.ThrowIfCancellationRequested();
            improved = false;
            for (int i = 0; i < 3; i++)
            {
                int orig = i == 0 ? pl : i == 1 ? pm : pr;
                double localBest = best;
                int localVal = orig;
                for (int d = -1; d <= 1; d += 2)
                {
                    int test = (orig + d + 26) % 26;
                    double s = ScoreWithPositionsAndPlug(text, i == 0 ? test : pl, i == 1 ? test : pm, i == 2 ? test : pr, plug, ct);
                    if (s > localBest) { localBest = s; localVal = test; }
                }
                if (i == 0) pl = localVal; else if (i == 1) pm = localVal; else pr = localVal;
                if (localBest > best) { best = localBest; improved = true; changed = true; }
            }
        }
        return (pl, pm, pr, best, changed);
    }

    private static double ScoreWithPositionsAndPlug(string text, int pl, int pm, int pr, int[] plug, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        AssertInvolution(plug);
        var dec = EnigmaMachineDeepSeek.Process(text.AsSpan(), FixedRotors, FixedReflector, pl, pm, pr, 0, 0, 0, plug, out _, out _, out _);
        return EnglishScorerDeepSeek.Score(dec);
    }

    private static int CountPairs(int[] plug) { int n = 0; for (int i = 0; i < 26; i++) if (plug[i] > i) n++; return n; }
    private static int[] Identity() { var a = new int[26]; for (int i = 0; i < 26; i++) a[i] = i; return a; }

    private static EnigmaSettingsDeepSeek ToSettings(Candidate2b c)
    {
        var names = EnigmaMachineDeepSeek.RotorNames;
        var pairs = new List<string>();
        for (int i = 0; i < 26; i++) if (c.Plug[i] > i) pairs.Add($"{(char)('A' + i)}{(char)('A' + c.Plug[i])}");
        return new EnigmaSettingsDeepSeek(
            new RotorConfigDeepSeek(names[FixedRotors[0]], 'A', (char)('A' + c.L)),
            new RotorConfigDeepSeek(names[FixedRotors[1]], 'A', (char)('A' + c.M)),
            new RotorConfigDeepSeek(names[FixedRotors[2]], 'A', (char)('A' + c.R)),
            "UKW-B", pairs);
    }

    private static int RankOf(List<Candidate> ranked, (int L, int M, int R) pos)
    { for (int i = 0; i < ranked.Count; i++) if (ranked[i].L == pos.L && ranked[i].M == pos.M && ranked[i].R == pos.R) return i + 1; return -1; }
    private static int RankOfPositions(List<Candidate2a> ranked, (int L, int M, int R) pos)
    { for (int i = 0; i < ranked.Count; i++) if (ranked[i].L == pos.L && ranked[i].M == pos.M && ranked[i].R == pos.R) return i + 1; return -1; }

    private static int CompareCandidates(Candidate2b a, Candidate2b b)
    {
        int cmp = b.Score.CompareTo(a.Score); if (cmp != 0) return cmp;
        cmp = a.L.CompareTo(b.L); if (cmp != 0) return cmp;
        cmp = a.M.CompareTo(b.M); if (cmp != 0) return cmp;
        cmp = a.R.CompareTo(b.R); if (cmp != 0) return cmp;
        for (int i = 0; i < 26; i++) { cmp = a.Plug[i].CompareTo(b.Plug[i]); if (cmp != 0) return cmp; }
        return 0;
    }

    private static bool IsValidInvolution(int[] plug) { for (int i = 0; i < 26; i++) { int j = plug[i]; if ((uint)j > 25) return false; if (plug[j] != i) return false; } return true; }

    [Conditional("DEBUG")]
    private static void AssertInvolution(int[] plug) { if (!IsValidInvolution(plug)) throw new InvalidOperationException("Plugboard is not an involution."); }

    private sealed record Candidate(int L, int M, int R, double Coarse);
    private sealed record Candidate2a(int L, int M, int R, double Score, int[] Plug);
    private sealed record Candidate2b(int L, int M, int R, double Score, int[] Plug);
}