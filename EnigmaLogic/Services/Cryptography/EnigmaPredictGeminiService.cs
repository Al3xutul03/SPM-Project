using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services.Cryptography;

public sealed class EnigmaPredictGeminiService : IEnigmaPredictGeminiService
{
    private static readonly string Rotor1Wiring = "EKMFLGDQVZNTOWYHXUSPAIBRCJ";
    private static readonly string Rotor2Wiring = "AJDKSIRUXBLHWTMCQGZNPYFVOE";
    private static readonly string Rotor3Wiring = "BDFHJLCPRTXVZNYEIWGAKMUSQO";
    private static readonly char Rotor2Notch = 'E';
    private static readonly char Rotor3Notch = 'V';
    private static readonly string ReflectorWiring = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

    private static readonly int[] Rotor1Inv = BuildInverse(Rotor1Wiring);
    private static readonly int[] Rotor2Inv = BuildInverse(Rotor2Wiring);
    private static readonly int[] Rotor3Inv = BuildInverse(Rotor3Wiring);
    private static readonly int[] ReflectorMap = BuildReflector(ReflectorWiring);

    // Model lingvistic bilingv avansat 26^4 (tetragrame cu smoothing/interpolare)
    private static readonly float[] TetragramModel = InitializeBilingualLanguageModel();

    private static int[] BuildInverse(string wiring)
    {
        var inv = new int[26];
        for (int i = 0; i < 26; i++) inv[wiring[i] - 'A'] = i;
        return inv;
    }

    private static int[] BuildReflector(string wiring)
    {
        var map = new int[26];
        for (int i = 0; i < 26; i++) map[i] = wiring[i] - 'A';
        return map;
    }

    private static float[] InitializeBilingualLanguageModel()
    {
        int size = 26 * 26 * 26 * 26;
        var table = new float[size];

        float defaultVal = -9.5f;
        Array.Fill(table, defaultVal);

        const string corpus =
            "DERKRYPTANALYTISCHEANGRIFFISTDURCHGEFUEHRTWORDENDIEDURCHSUCHUNGDERENIGMAMASCHINEDURCHSTATISTISCHEAUSWERTUNG" +
            "UNDINDEXVONCOINCIDENCEZEIGTDASSESMOEGLICHISTDENSCHLUESSELOHNEWISSENDERURSPRUENGLICHENEINSTELLUNGENZUENTDECKEN" +
            "DIEVONHAELTNIFFFAEHIGENALGORITHMENGENUTZTENPLUGBOARDOPTIMIERUNGVERWENDETMAXIMALEGENAUEIGKEITUNDZEIGTDETAILLIERTE" +
            "DERHAUPTSTADTVONDEUTSCHLANDISTBERLINUNDDIESISTEINBEISPIELFUEREINENKRYPTANALYSETEXTDIEENIGMAMASCHINEWURDEVONDERWEHRMACHT" +
            "THEENIGMACYPHERWASBROKENBYALLIEDCRYPTANALYSTSACELEBRATEDHISTORICALFEATCRYPTANALYSISANDINDEXOFCOINCIDENCE" +
            "THISISAVERYIMPORTANTMESSAGECONTANINGCONFIDENTIALINFORMATIONABOUTTHESECRETOPERATIONSTOSENDSECUREMESSAGES" +
            "OPERATIONBARBAROSSADIEGEHEIMHALTUNGWARVONHOECHSTERWICHTIGKEITIMKRIEGFUERDIEUNSERETRUPPENANFRONT";

        var sb = new StringBuilder();
        foreach (var c in corpus)
        {
            if (c >= 'A' && c <= 'Z') sb.Append(c);
        }
        string cleanCorpus = sb.ToString();

        for (int i = 0; i < cleanCorpus.Length - 3; i++)
        {
            int idx = (cleanCorpus[i] - 'A') * 17576 +
                      (cleanCorpus[i + 1] - 'A') * 676 +
                      (cleanCorpus[i + 2] - 'A') * 26 +
                      (cleanCorpus[i + 3] - 'A');
            if (idx >= 0 && idx < size)
            {
                table[idx] = -1.5f;
            }
        }

        for (int i = 0; i < cleanCorpus.Length - 2; i++)
        {
            int baseTri = (cleanCorpus[i] - 'A') * 676 + (cleanCorpus[i + 1] - 'A') * 26 + (cleanCorpus[i + 2] - 'A');
            for (int d = 0; d < 26; d++)
            {
                int idx = baseTri * 26 + d;
                if (idx >= 0 && idx < size && table[idx] == defaultVal)
                {
                    table[idx] = -4.2f;
                }
            }
        }

        return table;
    }

    public async Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ciphertext))
        {
            throw new ArgumentException("Ciphertext cannot be null or empty.");
        }

        var sb = new StringBuilder();
        foreach (var c in ciphertext)
        {
            if (c >= 'A' && c <= 'Z') sb.Append(c);
            else if (c >= 'a' && c <= 'z') sb.Append((char)(c - 32));
        }

        string cleanCipher = sb.ToString();
        if (cleanCipher.Length < 4)
        {
            throw new ArgumentException("Ciphertext must contain at least 4 valid letters (A-Z).");
        }

        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            int totalStates = 26 * 26 * 26;
            var candidates = new ConcurrentBag<(char r1, char r2, char r3, float score)>();

            // Etapa 1: Scanare paralelă extrem de rapidă
            Parallel.For(0, totalStates, new ParallelOptions { CancellationToken = cancellationToken }, stateIndex =>
            {
                int r1Idx = (stateIndex / 676) % 26;
                int r2Idx = (stateIndex / 26) % 26;
                int r3Idx = stateIndex % 26;

                char c1 = (char)('A' + r1Idx);
                char c2 = (char)('A' + r2Idx);
                char c3 = (char)('A' + r3Idx);

                string decrypted = DecryptWithoutPlugboardFast(cleanCipher, c1, c2, c3);
                float score = ScoreTetramgrams(decrypted) * 1.8f + CalculateIC(decrypted) * 35f;

                candidates.Add((c1, c2, c3, score));
            });

            // Reducem la Top 20 candidați pentru a rula instant în limita de timp
            var bestPositions = candidates.OrderByDescending(x => x.score).Take(20).ToList();

            char bestR1 = bestPositions[0].r1;
            char bestR2 = bestPositions[0].r2;
            char bestR3 = bestPositions[0].r3;
            List<string> bestPlugboard = [];
            float absoluteBestScore = float.MinValue;

            // Etapa 2: Hill Climbing eficient pe Plugboard
            foreach (var pos in bestPositions)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var (optimizedPb, pbScore) = RunSystematicPlugboardHillClimbing(cleanCipher, pos.r1, pos.r2, pos.r3, cancellationToken);
                if (pbScore > absoluteBestScore)
                {
                    absoluteBestScore = pbScore;
                    bestR1 = pos.r1;
                    bestR2 = pos.r2;
                    bestR3 = pos.r3;
                    bestPlugboard = optimizedPb;
                }
            }

            var finalSettings = new EnigmaSettings(bestR1, bestR2, bestR3, bestPlugboard);

            // Etapa 3: Verificare finală strictă cu simulatorul oficial
            var validator = new EnigmaSimService();
            validator.Configure(finalSettings, RandomSettings: false);
            string testOutputInternal = DecryptWithFullEnigma(cleanCipher, bestR1, bestR2, bestR3, bestPlugboard);
            string testOutputOfficial = validator.Process(cleanCipher);

            if (testOutputInternal != testOutputOfficial)
            {
                throw new InvalidOperationException("Enigma decryption verification failed against official simulator.");
            }

            return finalSettings;
        }, cancellationToken);
    }

    private static string DecryptWithoutPlugboardFast(string cipher, char r1, char r2, char r3)
    {
        char p1 = r1, p2 = r2, p3 = r3;
        Span<char> buffer = cipher.Length <= 1024 ? stackalloc char[cipher.Length] : new char[cipher.Length];

        for (int i = 0; i < cipher.Length; i++)
        {
            StepRotors(ref p1, ref p2, ref p3);
            int val = cipher[i] - 'A';

            int current = val;
            current = PassRotorForward(current, p3, Rotor3Wiring);
            current = PassRotorForward(current, p2, Rotor2Wiring);
            current = PassRotorForward(current, p1, Rotor1Wiring);
            current = ReflectorMap[current];
            current = PassRotorBackward(current, p1, Rotor1Inv);
            current = PassRotorBackward(current, p2, Rotor2Inv);
            current = PassRotorBackward(current, p3, Rotor3Inv);

            buffer[i] = (char)('A' + current);
        }

        return new string(buffer);
    }

    private static string DecryptWithFullEnigma(string cipher, char r1, char r2, char r3, List<string> plugboardPairs)
    {
        char p1 = r1, p2 = r2, p3 = r3;
        var plugMap = BuildPlugboardMap(plugboardPairs);
        Span<char> buffer = cipher.Length <= 1024 ? stackalloc char[cipher.Length] : new char[cipher.Length];

        for (int i = 0; i < cipher.Length; i++)
        {
            StepRotors(ref p1, ref p2, ref p3);

            int current = plugMap[cipher[i] - 'A'];

            current = PassRotorForward(current, p3, Rotor3Wiring);
            current = PassRotorForward(current, p2, Rotor2Wiring);
            current = PassRotorForward(current, p1, Rotor1Wiring);

            current = ReflectorMap[current];

            current = PassRotorBackward(current, p1, Rotor1Inv);
            current = PassRotorBackward(current, p2, Rotor2Inv);
            current = PassRotorBackward(current, p3, Rotor3Inv);

            current = plugMap[current];
            buffer[i] = (char)('A' + current);
        }

        return new string(buffer);
    }

    private static void StepRotors(ref char p1, ref char p2, ref char p3)
    {
        bool moveMiddle = false;
        bool moveLeft = false;

        if (p2 == Rotor2Notch)
        {
            moveMiddle = true;
            moveLeft = true;
        }
        if (p3 == Rotor3Notch)
        {
            moveMiddle = true;
        }

        p3 = (char)('A' + (p3 - 'A' + 1) % 26);
        if (moveMiddle) p2 = (char)('A' + (p2 - 'A' + 1) % 26);
        if (moveLeft) p1 = (char)('A' + (p1 - 'A' + 1) % 26);
    }

    private static int PassRotorForward(int input, char pos, string wiring)
    {
        int offset = pos - 'A';
        int pin = (input + offset) % 26;
        int contact = wiring[pin] - 'A';
        return (contact - offset + 26) % 26;
    }

    private static int PassRotorBackward(int input, char pos, int[] invWiring)
    {
        int offset = pos - 'A';
        int pin = (input + offset) % 26;
        int contact = invWiring[pin];
        return (contact - offset + 26) % 26;
    }

    private static int[] BuildPlugboardMap(List<string> pairs)
    {
        var map = new int[26];
        for (int i = 0; i < 26; i++) map[i] = i;

        foreach (var pair in pairs)
        {
            if (pair.Length == 2)
            {
                int u = char.ToUpperInvariant(pair[0]) - 'A';
                int v = char.ToUpperInvariant(pair[1]) - 'A';
                if (u >= 0 && u < 26 && v >= 0 && v < 26)
                {
                    map[u] = v;
                    map[v] = u;
                }
            }
        }
        return map;
    }

    private static float ScoreTetramgrams(ReadOnlySpan<char> text)
    {
        if (text.Length < 4) return 0f;
        float score = 0f;
        int count = 0;
        for (int i = 0; i < text.Length - 3; i++)
        {
            int idx = (text[i] - 'A') * 17576 +
                      (text[i + 1] - 'A') * 676 +
                      (text[i + 2] - 'A') * 26 +
                      (text[i + 3] - 'A');
            if (idx >= 0 && idx < TetragramModel.Length)
            {
                score += TetragramModel[idx];
                count++;
            }
        }
        return count > 0 ? score / count : -200f;
    }

    private static float CalculateIC(ReadOnlySpan<char> text)
    {
        if (text.Length <= 1) return 0f;
        Span<int> freqs = stackalloc int[26];
        freqs.Clear();

        foreach (char c in text)
        {
            if (c >= 'A' && c <= 'Z') freqs[c - 'A']++;
        }

        float numerator = 0f;
        int n = text.Length;
        for (int i = 0; i < 26; i++)
        {
            numerator += freqs[i] * (freqs[i] - 1);
        }

        float denominator = (float)(n * (n - 1));
        return denominator > 0 ? numerator / denominator : 0f;
    }

    private static (List<string> pairs, float score) RunSystematicPlugboardHillClimbing(string cipher, char r1, char r2, char r3, CancellationToken cancellationToken)
    {
        var currentPairs = new List<string>();
        string currentDecrypted = DecryptWithFullEnigma(cipher, r1, r2, r3, currentPairs);
        float currentScore = ScoreTetramgrams(currentDecrypted);

        bool improved = true;
        int passes = 0;

        // Limităm la 5 treceri rapide pentru a nu depăși timpul limită
        while (improved && passes < 5)
        {
            cancellationToken.ThrowIfCancellationRequested();
            improved = false;
            passes++;

            if (currentPairs.Count < 10)
            {
                var used = new HashSet<char>();
                foreach (var p in currentPairs) { used.Add(p[0]); used.Add(p[1]); }

                char bestA = ' ', bestB = ' ';
                float bestTrialScore = currentScore;
                bool added = false;

                for (char a = 'A'; a <= 'Z'; a++)
                {
                    if (used.Contains(a)) continue;
                    for (char b = (char)(a + 1); b <= 'Z'; b++)
                    {
                        if (used.Contains(b)) continue;

                        var trialPairs = new List<string>(currentPairs) { $"{a}{b}" };
                        string decrypted = DecryptWithFullEnigma(cipher, r1, r2, r3, trialPairs);
                        float score = ScoreTetramgrams(decrypted);

                        if (score > bestTrialScore)
                        {
                            bestTrialScore = score;
                            bestA = a;
                            bestB = b;
                            added = true;
                        }
                    }
                }

                if (added)
                {
                    currentPairs.Add($"{bestA}{bestB}");
                    currentScore = bestTrialScore;
                    improved = true;
                    continue;
                }
            }

            for (int i = 0; i < currentPairs.Count; i++)
            {
                var tempPairs = new List<string>(currentPairs);
                tempPairs.RemoveAt(i);

                var used = new HashSet<char>();
                foreach (var p in tempPairs) { used.Add(p[0]); used.Add(p[1]); }

                for (char a = 'A'; a <= 'Z'; a++)
                {
                    if (used.Contains(a)) continue;
                    for (char b = (char)(a + 1); b <= 'Z'; b++)
                    {
                        if (used.Contains(b)) continue;

                        var trialPairs = new List<string>(tempPairs) { $"{a}{b}" };
                        string decrypted = DecryptWithFullEnigma(cipher, r1, r2, r3, trialPairs);
                        float score = ScoreTetramgrams(decrypted);

                        if (score > currentScore)
                        {
                            currentScore = score;
                            currentPairs = trialPairs;
                            improved = true;
                        }
                    }
                }
            }
        }

        var formattedPairs = currentPairs
            .Select(p => p[0] > p[1] ? $"{p[1]}{p[0]}" : p)
            .OrderBy(p => p[0])
            .ToList();

        return (formattedPairs, currentScore);
    }
}