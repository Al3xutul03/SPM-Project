// EnigmaLogic/Services/EnglishScorerDeepSeek.cs
using System;
using System.Collections.Generic;

namespace EnigmaLogic.Services;

/// <summary>
/// Bilingual (German + English) log-probability language model, built at static
/// init from sample text embedded in this file.
///
/// The sample text is original prose written for this project only; it contains
/// no sentence or phrase from any test message (EXT-*, GermanText, GT-*).
///
/// Model: letter log-probability + bigram log-probability (with add-one smoothing)
/// + smoothed trigram bonus + Index of Coincidence. Per language, the score is
/// summed over the A-Z only. The bilingual score of a text is max(German, English).
/// </summary>
public static class EnglishScorerDeepSeek
{
    private const double SmoothingB = 0.5;

    private sealed class LanguageModel
    {
        public double[] LetterLog = new double[26];
        public double[] BigramLog = new double[26 * 26];
        public double[] TrigramLog = new double[26 * 26 * 26];
    }

    private static readonly LanguageModel German = BuildModel(GermanSample);
    private static readonly LanguageModel English = BuildModel(EnglishSample);

    // ------- original sample text, deliberately written for this project -------
    private const string GermanSample =
        "Der Wind strich ueber die Felder und bewegte leise das hohe Gras am Rand des Weges. " +
        "Ein alter Mann sass auf einer Bank vor dem kleinen Haus und beobachtete die Wolken, " +
        "die langsam ueber den Himmel zogen. Er dachte an die Jahre zurueck, in denen die Strasse " +
        "noch aus Lehm bestand und die Bauern mit Ochsenkarren zur Muehle fuhren. Heute fahren " +
        "Lastwagen und Traktoren, und die Kinder laufen mit ihren Raedern ueber den glatten Asphalt. " +
        "Am Abend versammelt sich die Familie am grossen Tisch, es gibt Brot, Kaese und Suppe, " +
        "und man spricht ueber die Arbeit auf dem Feld und die Nachrichten aus der Stadt. " +
        "Die Grossmutter erzaehlt Geschichten von frueher, von Reisen und von fremden Laendern, " +
        "und die Kleinen hoeren aufmerksam zu, bis ihnen die Augen zufallen. Draussen wird es " +
        "still, nur der Brunnen plaetschert leise, und irgendwo bellt ein Hund. Morgen werden " +
        "sie wieder frueh aufstehen, denn die Ernte wartet nicht, und das Wetter kann schnell " +
        "umschlagen. So vergehen die Tage in ruhigem Takt, und niemand wuenscht sich etwas anderes. " +
        "Die Kirche im Dorf laeutet am Sonntagmorgen, und die Menschen gehen mit ihren besten " +
        "Kleidern den Weg hinauf. Nach dem Gottesdienst treffen sie sich auf dem Platz, tauschen " +
        "Neuigkeiten aus und lachen ueber alte Geschichten. Die Kinder spielen zwischen den " +
        "Staenden des kleinen Marktes, auf dem Bauern Obst, Gemuese und frische Eier anbieten. " +
        "Am Nachmittag wird oft musiziert, ein Akkordeon, eine Geige und ein paar Stimmen, die " +
        "gemeinsam alte Lieder singen. Wenn der Herbst kommt, faerben sich die Blaetter rot und " +
        "golden, und die Luft riecht nach Holzfeuer und nassem Laub. Dann beginnt die Zeit der " +
        "Vorbereitungen fuer den Winter, Holz wird gehackt, die Fenster werden abgedichtet, und " +
        "die Speisekammer fuellt sich mit Vorraeten. Der erste Schnee bringt eine besondere Ruhe " +
        "mit sich, alles wirkt weich und weit, und die Wege werden zu schmalen Spuren im Weiss.";

    private const string EnglishSample =
        "The morning light came slowly through the tall windows of the old library, and the dust " +
        "moved in the beams as if it were breathing. A young woman sat at a wooden table near the " +
        "back, surrounded by open books and a pot of cold tea. She had been reading since before " +
        "sunrise, tracing the same paragraph again and again, hoping that a different order of " +
        "words might reveal something she had missed. Outside the street was quiet, only a boy on " +
        "a bicycle and a cat crossing the cobblestones in search of a warm corner. The city had a " +
        "way of waking slowly in autumn, as if it too were reluctant to leave the comfort of sleep. " +
        "In the afternoon she walked along the river, past the small market where farmers sold " +
        "apples, bread and cheese, and past the old bridge where painters set up their easels on " +
        "sunny days. She liked the way the light fell on the water, and the way strangers nodded to " +
        "each other as if they had known each other for years. On the way home she stopped at a " +
        "shop that sold paper and ink, and bought a notebook with a dark green cover. That evening " +
        "she wrote letters to friends she had not seen in a long time, describing the small things " +
        "that made the city feel like home. Later she sat by the window and watched the lamps come " +
        "on one by one along the street, and thought about the people living behind each lit pane. " +
        "The night was cool but not cold, and a gentle rain began to fall, tapping softly on the " +
        "glass. She closed the curtains and turned to her books again, and the hours passed quietly " +
        "until the clock in the hall struck midnight. There is a certain kind of peace in a room " +
        "full of books at night, she thought, a peace that has nothing to do with silence and " +
        "everything to do with the presence of many voices kept safely on the page. ";

    private static LanguageModel BuildModel(string sample)
    {
        var sb = new System.Text.StringBuilder(sample.Length);
        foreach (char ch in sample)
        {
            char c = char.ToUpperInvariant(ch);
            if (c >= 'A' && c <= 'Z') sb.Append(c);
        }
        string text = sb.ToString();

        var model = new LanguageModel();

        var letterCounts = new double[26];
        for (int i = 0; i < 26; i++) letterCounts[i] = 0;
        foreach (char c in text) letterCounts[c - 'A'] += 1;
        double letterTotal = text.Length + 26 * 1.0;
        for (int i = 0; i < 26; i++)
            model.LetterLog[i] = Math.Log((letterCounts[i] + 1.0) / letterTotal);

        var bigramCounts = new double[26 * 26];
        var trigramCounts = new double[26 * 26 * 26];
        for (int i = 1; i < text.Length; i++)
        {
            int a = text[i - 1] - 'A';
            int b = text[i] - 'A';
            bigramCounts[a * 26 + b] += 1;
            if (i >= 2)
            {
                int c0 = text[i - 2] - 'A';
                trigramCounts[(c0 * 26 + a) * 26 + b] += 1;
            }
        }

        // Bigram log-prob, add-one smoothed within each first letter.
        for (int a = 0; a < 26; a++)
        {
            double rowTotal = 0;
            for (int b = 0; b < 26; b++) rowTotal += bigramCounts[a * 26 + b];
            double denom = rowTotal + 26 * SmoothingB;
            for (int b = 0; b < 26; b++)
                model.BigramLog[a * 26 + b] = Math.Log((bigramCounts[a * 26 + b] + SmoothingB) / denom);
        }

        // Trigram log-prob, add-one smoothed within each (a,b) pair.
        for (int a = 0; a < 26; a++)
            for (int b = 0; b < 26; b++)
            {
                double rowTotal = 0;
                int baseIdx = (a * 26 + b) * 26;
                for (int c = 0; c < 26; c++) rowTotal += trigramCounts[baseIdx + c];
                double denom = rowTotal + 26 * SmoothingB;
                for (int c = 0; c < 26; c++)
                    model.TrigramLog[baseIdx + c] = Math.Log((trigramCounts[baseIdx + c] + SmoothingB) / denom);
            }

        return model;
    }

    private static double ScoreModel(string text, LanguageModel m)
    {
        if (text.Length == 0) return double.NegativeInfinity;

        double logp = 0;
        int n = 0;
        int prev1 = -1, prev2 = -1;

        foreach (char ch in text)
        {
            int idx = ch - 'A';
            if ((uint)idx > 25) { prev1 = prev2 = -1; continue; }

            logp += m.LetterLog[idx];
            n++;
            if (prev1 >= 0) logp += m.BigramLog[prev1 * 26 + idx];
            if (prev2 >= 0 && prev1 >= 0) logp += m.TrigramLog[(prev2 * 26 + prev1) * 26 + idx] * 0.5;

            prev2 = prev1;
            prev1 = idx;
        }

        var freq = new int[26];
        foreach (char ch in text) { int idx = ch - 'A'; if ((uint)idx <= 25) freq[idx]++; }
        double ioc = 0;
        if (n > 1)
        {
            for (int i = 0; i < 26; i++) ioc += freq[i] * (freq[i] - 1);
            ioc /= (double)(n * (n - 1));
        }

        // Logp is negative; convert to a comparable positive score by negating
        // the average negative log-likelihood and adding IoC.
        double perChar = n > 0 ? -logp / n : 0;
        return -perChar * 100.0 + ioc * 600.0;
    }

    /// <summary>Bilingual score. Returns max(German, English).</summary>
    public static double Score(string text)
    {
        if (text.Length < 4) return 0;
        double de = ScoreModel(text, German);
        double en = ScoreModel(text, English);
        return de > en ? de : en;
    }

    /// <summary>Stage-1 score: monogram IoC + doublet fraction. Language-agnostic.</summary>
    public static double CoarseScore(string text)
    {
        if (text.Length < 2) return 0;

        var freq = new int[26];
        int n = 0;
        foreach (char ch in text)
        {
            int idx = ch - 'A';
            if ((uint)idx > 25) continue;
            freq[idx]++; n++;
        }
        if (n < 2) return 0;

        double ioc = 0;
        for (int i = 0; i < 26; i++) ioc += freq[i] * (freq[i] - 1);
        ioc /= (double)(n * (n - 1));

        int doublets = 0;
        for (int i = 1; i < text.Length; i++)
        {
            char a = text[i - 1], b = text[i];
            if (a >= 'A' && a <= 'Z' && a == b) doublets++;
        }
        double doubletFraction = (double)doublets / Math.Max(1, text.Length - 1);

        return ioc * 1000.0 + (0.07 - doubletFraction) * 50.0;
    }
}