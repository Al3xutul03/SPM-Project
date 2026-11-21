// EnigmaLogic/Services/EnigmaPredictServiceDeepSeek.cs
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services;

public sealed class EnigmaPredictServiceDeepSeek : IEnigmaPredictServiceDeepSeek
{
    private const int PositionsPerRotor = 8;
    private const int TopK = 512;

    public Task<EnigmaSettingsDeepSeek> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(ciphertext);
        if (clean.Length < 20)
            throw new InvalidOperationException("Ciphertext too short for DeepSeek cryptanalysis (min 20 letters).");

        return Task.Run(() => CrackInternal(clean, cancellationToken), cancellationToken);
    }

    private static EnigmaSettingsDeepSeek CrackInternal(string clean, CancellationToken ct)
    {
        var perms = Permutations();
        object gate = new();

        // ---- Phase 1: exhaustive over positions for every rotor/reflector. ----
        var perConfig = new List<Candidate>(perms.Count * 2 * PositionsPerRotor);
        var options = new ParallelOptions { CancellationToken = ct };

        Parallel.For(0, perms.Count, options, ri =>
        {
            ct.ThrowIfCancellationRequested();
            var rot = perms[ri];
            for (int refl = 0; refl < 2; refl++)
            {
                var local = ExhaustivePositions(clean, rot, refl, ct);
                lock (gate) { perConfig.AddRange(local); }
            }
        });

        perConfig.Sort((x, y) => y.Score.CompareTo(x.Score));
        int k = Math.Min(TopK, perConfig.Count);
        var candidates = perConfig.GetRange(0, k);

        // ---- Phase 2: plugboard attack on every surviving candidate. ----
        var finals = new (Candidate c, double score, int[] plug)[k];

        Parallel.For(0, k, options, i =>
        {
            ct.ThrowIfCancellationRequested();
            var c = candidates[i];
            var plug = Identity();
            double score = FullPlugboardAttack(clean, c.Rot, c.Refl, (int[])c.Pos.Clone(), plug, ct);
            finals[i] = (c, score, plug);
        });

        double bestFinal = double.MinValue;
        Candidate? best = null;
        int[] bestPlug = Array.Empty<int>();

        foreach (var entry in finals)
        {
            if (entry.score > bestFinal)
            {
                bestFinal = entry.score;
                best = entry.c;
                bestPlug = entry.plug;
            }
        }

        var winner = best!;
        var pairs = new List<string>();
        for (int i = 0; i < 26; i++)
            if (bestPlug[i] > i) pairs.Add($"{(char)('A' + i)}{(char)('A' + bestPlug[i])}");

        var names = EnigmaMachineDeepSeek.RotorNames;
        return new EnigmaSettingsDeepSeek(
            new RotorConfigDeepSeek(names[winner.Rot[0]], 'A', (char)('A' + winner.Pos[0])),
            new RotorConfigDeepSeek(names[winner.Rot[1]], 'A', (char)('A' + winner.Pos[1])),
            new RotorConfigDeepSeek(names[winner.Rot[2]], 'A', (char)('A' + winner.Pos[2])),
            winner.Refl == 0 ? "UKW-B" : "UKW-C",
            pairs);
    }

    private static List<Candidate> ExhaustivePositions(string text, int[] rot, int refl, CancellationToken ct)
    {
        int[] id = Identity();
        var top = new List<(double score, int[] pos)>(PositionsPerRotor);

        for (int pl = 0; pl < 26; pl++)
        {
            ct.ThrowIfCancellationRequested();
            for (int pm = 0; pm < 26; pm++)
            {
                for (int pr = 0; pr < 26; pr++)
                {
                    var pos = new[] { pl, pm, pr };
                    double s = CoarseScore(text, rot, refl, pos, id);
                    InsertTop(top, s, pos, PositionsPerRotor);
                }
            }
        }

        var result = new List<Candidate>(top.Count);
        foreach (var (score, pos) in top)
            result.Add(new Candidate(rot, refl, pos, score));
        return result;
    }

    private static void InsertTop(List<(double score, int[] pos)> top, double score, int[] pos, int max)
    {
        if (top.Count < max)
        {
            top.Add((score, pos));
            top.Sort((a, b) => b.score.CompareTo(a.score));
            return;
        }
        if (score <= top[^1].score) return;
        top[^1] = (score, pos);
        top.Sort((a, b) => b.score.CompareTo(a.score));
    }

    private static double CoarseScore(string text, int[] rot, int refl, int[] pos, int[] plug)
    {
        var dec = EnigmaMachineDeepSeek.Process(
            text.AsSpan(), rot, refl, pos[0], pos[1], pos[2], 0, 0, 0, plug,
            out _, out _, out _);
        return EnglishScorerDeepSeek.CoarseScore(dec);
    }

    private static double FullPlugboardAttack(
        string text, int[] rot, int refl, int[] startPos, int[] plug, CancellationToken ct)
    {
        int[] pos = startPos;
        double score = ScoreWith(text, rot, refl, pos, plug, ct);

        var (p1, s1, _) = HillClimbWithPlug(text, rot, refl, pos, plug, ct);
        pos = p1; score = s1;

        for (int iter = 0; iter < 13; iter++)
        {
            ct.ThrowIfCancellationRequested();

            if (!TryBestPlug(text, rot, refl, pos, plug, score, ct, out int ba, out int bb, out double newScore))
                break;

            plug[ba] = bb; plug[bb] = ba;
            score = newScore;

            var (p2, s2, improved) = HillClimbWithPlug(text, rot, refl, pos, plug, ct);
            pos = p2; score = s2;

            if (!improved && !HasRoomForMorePlugs(plug))
                break;
        }

        Array.Copy(pos, startPos, 3);
        return score;
    }

    private static bool TryBestPlug(
        string text, int[] rot, int refl, int[] pos, int[] plug, double currentScore,
        CancellationToken ct, out int bestA, out int bestB, out double bestScore)
    {
        bestA = -1; bestB = -1; bestScore = currentScore;
        double bestGain = 0;

        for (int a = 0; a < 26; a++)
        {
            if (plug[a] != a) continue;
            for (int b = a + 1; b < 26; b++)
            {
                if (plug[b] != b) continue;
                plug[a] = b; plug[b] = a;
                double s = ScoreWith(text, rot, refl, pos, plug, ct);
                if (s - currentScore > bestGain)
                {
                    bestGain = s - currentScore;
                    bestA = a; bestB = b; bestScore = s;
                }
                plug[a] = a; plug[b] = b;
            }
        }

        return bestGain > 0;
    }

    private static bool HasRoomForMorePlugs(int[] plug)
    {
        for (int i = 0; i < 26; i++) if (plug[i] == i) return true;
        return false;
    }

    private static (int[] Positions, double Score, bool Improved) HillClimbWithPlug(
        string text, int[] rot, int refl, int[] startPos, int[] plug, CancellationToken ct)
    {
        int[] pos = (int[])startPos.Clone();
        double sc = ScoreWith(text, rot, refl, pos, plug, ct);
        double baseline = sc;
        bool improved = true;
        int guard = 0;

        while (improved && guard++ < 300)
        {
            ct.ThrowIfCancellationRequested();
            improved = false;
            for (int i = 0; i < 3; i++)
            {
                int orig = pos[i];
                double localBest = sc;
                int localVal = orig;
                for (int d = -1; d <= 1; d += 2)
                {
                    pos[i] = (orig + d + 26) % 26;
                    double s = ScoreWith(text, rot, refl, pos, plug, ct);
                    if (s > localBest) { localBest = s; localVal = pos[i]; }
                }
                pos[i] = localVal;
                if (localBest > sc) { sc = localBest; improved = true; }
            }
        }

        return (pos, sc, sc > baseline);
    }

    private static double ScoreWith(string text, int[] rot, int refl, int[] pos, int[] plug, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var dec = EnigmaMachineDeepSeek.Process(
            text.AsSpan(), rot, refl, pos[0], pos[1], pos[2], 0, 0, 0, plug,
            out _, out _, out _);
        return EnglishScorerDeepSeek.Score(dec);
    }

    private static int[] Identity() { var a = new int[26]; for (int i = 0; i < 26; i++) a[i] = i; return a; }

    private static List<int[]> Permutations()
    {
        var res = new List<int[]>();
        for (int a = 0; a < 5; a++)
            for (int b = 0; b < 5; b++)
            {
                if (b == a) continue;
                for (int c = 0; c < 5; c++)
                {
                    if (c == a || c == b) continue;
                    res.Add(new[] { a, b, c });
                }
            }
        return res;
    }

    private sealed record Candidate(int[] Rot, int Refl, int[] Pos, double Score);
}