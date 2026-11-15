// FILE: EnigmaLogic/Services/EnigmaPredictServiceDeepSeek.cs
using System; 
using System.Collections.Generic; 
using System.Threading; 
using System.Threading.Tasks; 
using EnigmaLogic.Models; 
using EnigmaLogic.Services.Abstractions;


namespace EnigmaLogic.Services;

public sealed class EnigmaPredictServiceDeepSeek : IEnigmaPredictServiceDeepSeek
{
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
        double bestScore = double.MinValue;
        int[]? bestRot = null;
        int bestRefl = 0;
        int[]? bestOff = null;
        object gate = new();

        var options = new ParallelOptions { CancellationToken = ct };
        Parallel.For(0, perms.Count, options, ri =>
        {
            ct.ThrowIfCancellationRequested();
            var rot = perms[ri];
            for (int refl = 0; refl < 2; refl++)
            {
                var (score, off) = HillClimb(clean, rot, refl, ct);
                lock (gate)
                {
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestRot = rot;
                        bestRefl = refl;
                        bestOff = off;
                    }
                }
            }
        });

        var plug = Identity();
        double cur = ScoreWith(clean, bestRot!, bestRefl, bestOff!, plug, ct);
        for (int iter = 0; iter < 13; iter++)
        {
            ct.ThrowIfCancellationRequested();
            double bestGain = 0;
            int ba = -1, bb = -1;

            for (int a = 0; a < 26; a++)
            {
                if (plug[a] != a) continue;
                for (int b = a + 1; b < 26; b++)
                {
                    if (plug[b] != b) continue;
                    plug[a] = b; plug[b] = a;
                    double s = ScoreWith(clean, bestRot!, bestRefl, bestOff!, plug, ct);
                    if (s - cur > bestGain) { bestGain = s - cur; ba = a; bb = b; }
                    plug[a] = a; plug[b] = b;
                }
            }

            if (bestGain <= 0) break;
            plug[ba] = bb; plug[bb] = ba; cur += bestGain;
        }

        var pairs = new List<string>();
        for (int i = 0; i < 26; i++)
            if (plug[i] > i) pairs.Add($"{(char)('A' + i)}{(char)('A' + plug[i])}");

        var names = EnigmaMachineDeepSeek.RotorNames;
        return new EnigmaSettingsDeepSeek(
        new RotorConfigDeepSeek(names[bestRot![0]], 'A', (char)('A' + bestOff![0])),
        new RotorConfigDeepSeek(names[bestRot[1]], 'A', (char)('A' + bestOff[1])),
        new RotorConfigDeepSeek(names[bestRot[2]], 'A', (char)('A' + bestOff[2])),
        bestRefl == 0 ? "UKW-B" : "UKW-C",
        pairs);
    }

    private static (double Score, int[] Offsets) HillClimb(string text, int[] rot, int refl, CancellationToken ct)
    {
        double best = double.MinValue;
        int[] bestOff = { 0, 0, 0 };
        var rnd = new Random(rot[0] * 10000 + rot[1] * 100 + rot[2] * 3 + refl);
        int[] id = Identity();

        for (int restart = 0; restart < 10; restart++)
        {
            ct.ThrowIfCancellationRequested();
            int[] off = { rnd.Next(26), rnd.Next(26), rnd.Next(26) };
            double sc = ScoreWith(text, rot, refl, off, id, ct);
            bool improved = true;
            int guard = 0;

            while (improved && guard++ < 250)
            {
                improved = false;
                for (int i = 0; i < 3; i++)
                {
                    int orig = off[i];
                    double localBest = sc;
                    int localVal = orig;

                    for (int d = -1; d <= 1; d += 2)
                    {
                        off[i] = (orig + d + 26) % 26;
                        double s = ScoreWith(text, rot, refl, off, id, ct);
                        if (s > localBest) { localBest = s; localVal = off[i]; }
                    }

                    off[i] = localVal;
                    if (localBest > sc) { sc = localBest; improved = true; }
                }
            }

            if (sc > best) { best = sc; bestOff = (int[])off.Clone(); }
        }

        return (best, bestOff);
    }

    private static double ScoreWith(string text, int[] rot, int refl, int[] off, int[] plug, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var dec = EnigmaMachineDeepSeek.Process(
        text.AsSpan(), rot, refl, off[0], off[1], off[2], plug,
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
}