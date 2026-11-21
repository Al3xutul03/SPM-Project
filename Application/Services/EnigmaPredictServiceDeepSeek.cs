// EnigmaLogic/Services/EnigmaPredictServiceDeepSeek.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services;

/// <summary>
/// DeepSeek ciphertext-only attack for this project's machine.
///
/// The project's EnigmaSettings fixes rotors to I-II-III, rings to AAA and the
/// reflector to UKW-B, so the cracker searches only that one rotor/reflector
/// combination. Search space per message is therefore 26^3 window positions plus
/// a plugboard, not 120 x 26^3.
///
///   1. STAGE 1  Exhaustive over 17,576 positions, scored by CoarseScore
///               (monogram IoC + doublet fraction; language-agnostic and
///               plugboard-tolerant because the plugboard is a bijection).
///               Keep all positions in memory; rank by CoarseScore.
///
///   2. STAGE 2a Cheap plug pass. On the top N (length-adaptive) positions,
///               run a bounded add-only plug search (max 3 pairs, no position
///               hill-climb). Prune to the top 200.
///
///   3. STAGE 2b Full plug search on those 200. Moves: add best pair, remove a
///               pair, swap one end of a pair with a free letter, relink two
///               pairs. Position hill-climb after each accepted move. Bilingual
///               score (German + English log-prob), stop adding pairs when the
///               gain is below epsilon.
///
///   4. Deterministic tournament: collect all final results, sort by
///               (score desc, rotor, reflector, positions, plugboard), take the
///               first. Returns the STAGE-2 positions, not the STAGE-1 candidate.
///
/// The machine's rings are not searched. They are reported as AAA.
/// </summary>
public sealed class EnigmaPredictServiceDeepSeek : IEnigmaPredictServiceDeepSeek, IEnigmaPredictDiagnosticDeepSeek
{
    // Fixed machine configuration, per project's EnigmaSettings.
    private static readonly int[] FixedRotors = { 0, 1, 2 };
    private const int FixedReflector = 0;

    // Length-adaptive candidate counts for stage 2a.
    private const int ShortThreshold = 100;
    private const int ShortCandidates = 5000;
    private const int LongCandidates = 2000;

    // Stage 2b candidate count.
    private const int Stage2bCandidates = 200;

    // Stage 2a/2b limits.
    private const int CheapMaxPlugs = 3;
    private const int FullMaxPlugs = 13;
    private const double StopEpsilon = 0.5;

    public Task<EnigmaSettingsDeepSeek> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(ciphertext);
        if (clean.Length < 20)
            throw new InvalidOperationException("Ciphertext too short for DeepSeek cryptanalysis (min 20 letters).");

        return Task.Run(() => CrackInternal(clean, cancellationToken), cancellationToken);
    }

    public Task<CrackDiagnosticDeepSeek> DiagnoseAsync(
        string ciphertext,
        (int L, int M, int R) truePositions,
        IReadOnlyList<string> truePlugboard,
        CancellationToken cancellationToken = default)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(ciphertext);
        if (clean.Length < 20)
            throw new InvalidOperationException("Ciphertext too short for DeepSeek diagnostics.");

        return Task.Run(() => DiagnoseInternal(clean, truePositions, truePlugboard, cancellationToken), cancellationToken);
    }

    private static EnigmaSettingsDeepSeek CrackInternal(string clean, CancellationToken ct)
    {
        var sw1 = Stopwatch.StartNew();
        var ranked = Stage1(clean, ct);
        sw1.Stop();

        int cheap = clean.Length < ShortThreshold ? ShortCandidates : LongCandidates;
        cheap = Math.Min(cheap, ranked.Count);

        var sw2a = Stopwatch.StartNew();
        var stage2a = Stage2a(clean, ranked, cheap, ct);
        sw2a.Stop();

        int expensive = Math.Min(Stage2bCandidates, stage2a.Count);

        var sw2b = Stopwatch.StartNew();
        var stage2b = Stage2b(clean, stage2a, expensive, ct);
        sw2b.Stop();

        stage2b.Sort(CompareCandidates);
        var winner = stage2b[0];

        return ToSettings(winner);
    }

    private static CrackDiagnosticDeepSeek DiagnoseInternal(
        string clean,
        (int L, int M, int R) truePositions,
        IReadOnlyList<string> truePlugboard,
        CancellationToken ct)
    {
        var sw1 = Stopwatch.StartNew();
        var ranked = Stage1(clean, ct);
        sw1.Stop();

        int trueRank1 = RankOf(ranked, truePositions);

        int cheap = clean.Length < ShortThreshold ? ShortCandidates : LongCandidates;
        cheap = Math.Min(cheap, ranked.Count);

        var sw2a = Stopwatch.StartNew();
        var stage2a = Stage2a(clean, ranked, cheap, ct);
        sw2a.Stop();

        int trueRank2a = RankOfPositions(stage2a, truePositions);

        int expensive = Math.Min(Stage2bCandidates, stage2a.Count);

        var sw2b = Stopwatch.StartNew();
        var stage2b = Stage2b(clean, stage2a, expensive, ct);
        sw2b.Stop();

        return new CrackDiagnosticDeepSeek(
            trueRank1,
            trueRank2a,
            sw1.Elapsed.TotalMilliseconds,
            sw2a.Elapsed.TotalMilliseconds,
            sw2b.Elapsed.TotalMilliseconds,
            ranked.Count,
            stage2a.Count,
            stage2b.Count);
    }

    // ------------------------------------------------------------------
    // Stage 1
    // ------------------------------------------------------------------
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
                    var dec = EnigmaMachineDeepSeek.Process(
                        text.AsSpan(), FixedRotors, FixedReflector, pl, pm, pr, 0, 0, 0, id,
                        out _, out _, out _);
                    double score = EnglishScorerDeepSeek.CoarseScore(dec);
                    list.Add(new Candidate(pl, pm, pr, score));
                }
        }

        list.Sort((a, b) => b.Coarse.CompareTo(a.Coarse));
        return list;
    }

    // ------------------------------------------------------------------
    // Stage 2a: cheap plug pass, add-only, max 3 pairs, no position hill-climb.
    // ------------------------------------------------------------------
    private static List<Candidate2a> Stage2a(string text, List<Candidate> ranked, int count, CancellationToken ct)
    {
        var results = new Candidate2a[count];
        var options = new ParallelOptions { CancellationToken = ct };

        Parallel.For(0, count, options, i =>
        {
            ct.ThrowIfCancellationRequested();
            var c = ranked[i];
            var plug = Identity();
            double score = ScoreWithPositionsAndPlug(text, c.L, c.M, c.R, plug, ct);

            for (int add = 0; add < CheapMaxPlugs; add++)
            {
                if (!TryBestAdd(text, c.L, c.M, c.R, plug, score, ct, out int ba, out int bb, out double newScore))
                    break;
                plug[ba] = bb; plug[bb] = ba;
                score = newScore;
            }

            results[i] = new Candidate2a(c.L, c.M, c.R, score, plug);
        });

        var list = new List<Candidate2a>(results);
        list.Sort((a, b) => b.Score.CompareTo(a.Score));
        return list;
    }

    // ------------------------------------------------------------------
    // Stage 2b: full plug search with add / remove / swap / relink plus position hill-climb.
    // ------------------------------------------------------------------
    private static List<Candidate2b> Stage2b(string text, List<Candidate2a> ranked, int count, CancellationToken ct)
    {
        var results = new Candidate2b[count];
        var options = new ParallelOptions { CancellationToken = ct };

        Parallel.For(0, count, options, i =>
        {
            ct.ThrowIfCancellationRequested();
            var c = ranked[i];
            var plug = (int[])c.Plug.Clone();
            int pl = c.L, pm = c.M, pr = c.R;
            double score = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);

            for (int round = 0; round < 24; round++)
            {
                ct.ThrowIfCancellationRequested();

                bool changed = false;

                if (TryBestAdd(text, pl, pm, pr, plug, score, ct, out int ba, out int bb, out double s2))
                {
                    plug[ba] = bb; plug[bb] = ba;
                    score = s2; changed = true;
                }

                if (TryBestRemove(text, pl, pm, pr, plug, score, ct, out double s3))
                {
                    score = s3; changed = true;
                }

                if (TryBestSwapEnd(text, pl, pm, pr, plug, score, ct, out double s4))
                {
                    score = s4; changed = true;
                }

                if (TryBestRelink(text, pl, pm, pr, plug, score, ct, out double s5))
                {
                    score = s5; changed = true;
                }

                var (npL, npM, npR, s6, posChanged) = HillClimbPositions(text, pl, pm, pr, plug, score, ct);
                if (posChanged) { pl = npL; pm = npM; pr = npR; score = s6; changed = true; }

                if (!changed) break;
            }

            results[i] = new Candidate2b(pl, pm, pr, score, plug);
        });

        return new List<Candidate2b>(results);
    }

    private static bool TryBestAdd(
        string text, int pl, int pm, int pr, int[] plug, double current,
        CancellationToken ct, out int bestA, out int bestB, out double bestScore)
    {
        bestA = -1; bestB = -1; bestScore = current;
        double bestGain = StopEpsilon;
        int pairs = CountPairs(plug);
        if (pairs >= FullMaxPlugs) return false;

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

    private static bool TryBestRemove(
        string text, int pl, int pm, int pr, int[] plug, double current,
        CancellationToken ct, out double bestScore)
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

    private static bool TryBestSwapEnd(
        string text, int pl, int pm, int pr, int[] plug, double current,
        CancellationToken ct, out double bestScore)
    {
        bestScore = current;
        double bestGain = StopEpsilon;
        int[] saved = (int[])plug.Clone();

        for (int a = 0; a < 26; a++)
        {
            int b = plug[a];
            if (b == a) continue;

            for (int c = 0; c < 26; c++)
            {
                if (c == a || c == b || plug[c] != c) continue;

                plug[a] = a; plug[b] = b;
                plug[a] = c; plug[c] = a;
                double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);
                if (s - current > bestGain) { bestGain = s - current; bestScore = s; Array.Copy(plug, saved, 26); }
                else { plug[a] = a; plug[c] = c; plug[a] = b; plug[b] = a; }

                plug[a] = a; plug[b] = b;
                plug[b] = c; plug[c] = b;
                s = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);
                if (s - current > bestGain) { bestGain = s - current; bestScore = s; Array.Copy(plug, saved, 26); }
                else { plug[b] = b; plug[c] = c; plug[a] = b; plug[b] = a; }
            }
        }

        if (bestGain > StopEpsilon) { Array.Copy(saved, plug, 26); return true; }
        return false;
    }

    private static bool TryBestRelink(
        string text, int pl, int pm, int pr, int[] plug, double current,
        CancellationToken ct, out double bestScore)
    {
        bestScore = current;
        double bestGain = StopEpsilon;
        int[] saved = (int[])plug.Clone();

        for (int a = 0; a < 26; a++)
        {
            int b = plug[a];
            if (b == a) continue;
            for (int c = a + 1; c < 26; c++)
            {
                int d = plug[c];
                if (d == c) continue;
                if (c == b || d == a) continue;

                plug[a] = a; plug[b] = b; plug[c] = c; plug[d] = d;
                plug[a] = c; plug[c] = a; plug[b] = d; plug[d] = b;
                double s = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);
                if (s - current > bestGain) { bestGain = s - current; bestScore = s; Array.Copy(plug, saved, 26); }
                else { plug[a] = a; plug[b] = b; plug[c] = c; plug[d] = d; plug[a] = b; plug[b] = a; plug[c] = d; plug[d] = c; }

                plug[a] = a; plug[b] = b; plug[c] = c; plug[d] = d;
                plug[a] = d; plug[d] = a; plug[b] = c; plug[c] = b;
                s = ScoreWithPositionsAndPlug(text, pl, pm, pr, plug, ct);
                if (s - current > bestGain) { bestGain = s - current; bestScore = s; Array.Copy(plug, saved, 26); }
                else { plug[a] = a; plug[b] = b; plug[c] = c; plug[d] = d; plug[a] = b; plug[b] = a; plug[c] = d; plug[d] = c; }
            }
        }

        if (bestGain > StopEpsilon) { Array.Copy(saved, plug, 26); return true; }
        return false;
    }

    private static (int L, int M, int R, double Score, bool Changed) HillClimbPositions(
        string text, int pl, int pm, int pr, int[] plug, double current, CancellationToken ct)
    {
        double best = current;
        bool changed = false;
        bool improved = true;
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
                    double s = ScoreWithPositionsAndPlug(
                        text,
                        i == 0 ? test : pl,
                        i == 1 ? test : pm,
                        i == 2 ? test : pr,
                        plug, ct);
                    if (s > localBest) { localBest = s; localVal = test; }
                }

                if (i == 0) pl = localVal;
                else if (i == 1) pm = localVal;
                else pr = localVal;

                if (localBest > best) { best = localBest; improved = true; changed = true; }
            }
        }

        return (pl, pm, pr, best, changed);
    }

    private static double ScoreWithPositionsAndPlug(string text, int pl, int pm, int pr, int[] plug, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var dec = EnigmaMachineDeepSeek.Process(
            text.AsSpan(), FixedRotors, FixedReflector, pl, pm, pr, 0, 0, 0, plug,
            out _, out _, out _);
        return EnglishScorerDeepSeek.Score(dec);
    }

    private static int CountPairs(int[] plug)
    {
        int n = 0;
        for (int i = 0; i < 26; i++) if (plug[i] > i) n++;
        return n;
    }

    private static int[] Identity() { var a = new int[26]; for (int i = 0; i < 26; i++) a[i] = i; return a; }

    private static EnigmaSettingsDeepSeek ToSettings(Candidate2b c)
    {
        var names = EnigmaMachineDeepSeek.RotorNames;
        var pairs = new List<string>();
        for (int i = 0; i < 26; i++)
            if (c.Plug[i] > i) pairs.Add($"{(char)('A' + i)}{(char)('A' + c.Plug[i])}");
        return new EnigmaSettingsDeepSeek(
            new RotorConfigDeepSeek(names[FixedRotors[0]], 'A', (char)('A' + c.L)),
            new RotorConfigDeepSeek(names[FixedRotors[1]], 'A', (char)('A' + c.M)),
            new RotorConfigDeepSeek(names[FixedRotors[2]], 'A', (char)('A' + c.R)),
            "UKW-B",
            pairs);
    }

    private static int RankOf(List<Candidate> ranked, (int L, int M, int R) pos)
    {
        for (int i = 0; i < ranked.Count; i++)
            if (ranked[i].L == pos.L && ranked[i].M == pos.M && ranked[i].R == pos.R) return i + 1;
        return -1;
    }

    private static int RankOfPositions(List<Candidate2a> ranked, (int L, int M, int R) pos)
    {
        for (int i = 0; i < ranked.Count; i++)
            if (ranked[i].L == pos.L && ranked[i].M == pos.M && ranked[i].R == pos.R) return i + 1;
        return -1;
    }

    private static int CompareCandidates(Candidate2b a, Candidate2b b)
    {
        int cmp = b.Score.CompareTo(a.Score);
        if (cmp != 0) return cmp;
        cmp = a.L.CompareTo(b.L);
        if (cmp != 0) return cmp;
        cmp = a.M.CompareTo(b.M);
        if (cmp != 0) return cmp;
        cmp = a.R.CompareTo(b.R);
        if (cmp != 0) return cmp;
        for (int i = 0; i < 26; i++)
        {
            cmp = a.Plug[i].CompareTo(b.Plug[i]);
            if (cmp != 0) return cmp;
        }
        return 0;
    }

    private sealed record Candidate(int L, int M, int R, double Coarse);
    private sealed record Candidate2a(int L, int M, int R, double Score, int[] Plug);
    private sealed record Candidate2b(int L, int M, int R, double Score, int[] Plug);
}