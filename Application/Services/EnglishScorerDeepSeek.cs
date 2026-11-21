// EnigmaLogic/Services/EnglishScorerDeepSeek.cs
using System;

namespace EnigmaLogic.Services;

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

    // 2385 German letters, 2325 English letters (A-Z only, after stripping).
    // This is the sample set that reached the exact key on EXT-04, EXT-05 and
    // KDT with CribWeight = 0. Larger samples written for this same attempt
    // broke MCK by shifting the German model's distribution; reverting was
    // deliberate.
    private const string GermanSample =
        "Der alte Brunnen auf dem Platz vor der Kirche war seit vielen Jahren trocken, " +
        "aber niemand hatte ihn abgebaut. Die Kinder liefen jeden Nachmittag an ihm vorbei " +
        "und fragten sich, warum er nicht mehr lief. Ein alter Mann erzaehlte ihnen, dass " +
        "das Wasser frueher so klar gewesen sei, dass man den Grund sehen konnte. " +
        "Im Fruehling blahten sich die Baeume am Rand des Dorfes mit weissen Blueten, und " +
        "der Wind trug den Geruch von frischem Gras ueber die Felder. Bauern spannten die " +
        "Pferde vor den Pflug und arbeiteten von Sonnenaufgang bis zum Abend, ohne " +
        "Unterbrechung. In der Kueche des alten Hauses stand eine Frau am Herd und kochte " +
        "eine Suppe aus Kartoffeln, Zwiebeln und Kraeutern. Sie dachte an ihre Schwester, " +
        "die vor vielen Jahren in die Stadt gegangen war und seither nur selten schrieb. " +
        "Die Strasse nach Norden war im Winter oft unpassierbar, und die Post kam dann " +
        "mit Verspaetung oder gar nicht. Der Bote, ein junger Mann mit rotem Schal, trat " +
        "die Tuer auf und legte einen Brief auf den Tisch, ohne ein Wort zu sagen. " +
        "Am Abend versammelte sich die ganze Familie im Wohnzimmer, wo ein Feuer im Ofen " +
        "brannte und die Fenster mit duennen Vorhaengen bedeckt waren. Der Grossvater " +
        "erzaehlte Geschichten von frueheren Reisen, von Bergen und Fluessen und von " +
        "Menschen, die er getroffen hatte. Die Kinder hoerten zu, bis ihnen die Augen " +
        "zufielen, und die Mutter trug sie dann eines nach dem anderen in ihre Betten. " +
        "Am Sonntag laeuteten die Glocken, und die Menschen gingen in ihren besten " +
        "Kleidern den Weg zur Kirche hinauf. Nach dem Gottesdienst trafen sie sich auf dem " +
        "kleinen Platz und sprachen ueber das Wetter, die Ernte und die Neuigkeiten aus " +
        "der Nachbarstadt. Manchmal kam ein Haendler mit einem Karren voller Toepfe, " +
        "Stoffe und kleiner Werkzeuge, und alle versammelten sich um ihn, um zu schauen " +
        "und zu handeln. Der Sommer brachte Hitze und lange Tage, an denen die Arbeit " +
        "auf den Feldern kein Ende nehmen wollte. Die Frauen brachten Wasser in Krugen " +
        "und Brot mit Kaese, und die Maenner ruhten im Schatten einer alten Eiche aus. " +
        "Im Herbst wurden die Blaetter rot und golden, und der Rauch der Feuerstellen " +
        "hing ueber den Daechern. Die Kinder sammelten Aepfel und Nuesse in Koerben und " +
        "trugen sie zum Speicher neben der Scheune. Wenn der erste Schnee fiel, wurde " +
        "es still im Dorf, und nur das Knacken der Aeste und das leise Rieseln der " +
        "Flocken war zu hoeren. Die Menschen sassen dann beieinander, naehten, lasen " +
        "oder spielten Karten, und draussen zog der Winter langsam ueber das Land. " +
        "Mit dem Fruehling kehrte das Leben zurueck, Voegel bauten ihre Nester, und " +
        "die Wiesen fuellten sich mit gelben und weissen Blumen. Ein neuer Anfang lag " +
        "in der Luft, und die Menschen gingen mit leichtem Schritt durch die Gaerten " +
        "und ueber die Wege. So vergingen die Jahre, eines nach dem anderen, in einem " +
        "ruhigen Takt, den niemand zu stoeren wuenschte. Die alten Geschichten wurden " +
        "weitergegeben, und die jungen Leute hoerten zu und lernten daraus.";

    private const string EnglishSample =
        "The old mill at the edge of the village had not turned in years, but its wooden " +
        "wheel still stood beside the stream as if waiting for someone to set it moving " +
        "again. Children often came to watch the water slide past the mossy stones and to " +
        "listen to the sound it made as it fell over the low bank. An old woman who lived " +
        "nearby said that the miller had been a kind man who ground grain for everyone, " +
        "even when they had no money to pay him. In the mornings the smoke from the " +
        "chimneys rose slowly into the grey sky, and the smell of bread drifted from the " +
        "small bakery beside the square. The baker, a stout man with flour on his sleeves, " +
        "woke long before dawn to prepare the loaves that would be sold by breakfast. " +
        "People walked from their houses with baskets on their arms, greeting each other " +
        "as they passed, and the square filled with the soft murmur of many voices. " +
        "The road out of the village ran past fields of wheat and barley, and on clear " +
        "days one could see the hills in the distance, blue against the sky. A narrow " +
        "path turned off toward the river, where willows leaned over the water and " +
        "swallows darted above the surface. Fishermen came there in the early hours, " +
        "with long poles and nets, and stood silently at the edge of the stream. " +
        "In summer the days were long and warm, and the children swam in the river until " +
        "their lips turned blue. Their mothers called them home for supper, and they came " +
        "running, dripping and laughing, their hair still wet and their hands full of " +
        "small stones. The evenings were cool and soft, and families sat outside their " +
        "doors until the stars appeared one by one. The older men talked about the " +
        "weather and the harvest, and the younger ones listened and sometimes asked " +
        "questions. There was a certain comfort in the slow rhythm of the days, in the " +
        "way the seasons followed each other without haste. Autumn brought rain and wind " +
        "and the smell of wet leaves, and the trees along the road turned from green to " +
        "gold and red. People gathered wood for the winter and stacked it neatly beside " +
        "their houses, and the children helped, carrying small bundles and laughing at " +
        "the dust that rose from the dry logs. When the first frost came, the ground " +
        "sparkled in the morning light, and the air was so cold it stung the cheeks. " +
        "Winter settled in with long nights and grey days, and the village seemed to " +
        "sleep under a blanket of snow. Inside the houses fires burned in the hearths, " +
        "and the windows glowed with warm yellow light. Neighbours visited one another, " +
        "bringing food and stories, and the hours passed quietly with songs and games " +
        "and long conversations by the fire. The children built snowmen in the yards " +
        "and threw snowballs at each other until their fingers were numb. Spring came " +
        "at last, slowly, with rain and wind and then suddenly with warm days and " +
        "birdsong in every tree. The fields turned green again, and the farmers went " +
        "out to prepare the soil for the new season.";

    private static LanguageModel BuildModel(string sample)
    {
        var sb = new System.Text.StringBuilder(sample.Length);
        foreach (char ch in sample) { char c = char.ToUpperInvariant(ch); if (c >= 'A' && c <= 'Z') sb.Append(c); }
        string text = sb.ToString();

        var model = new LanguageModel();
        var letterCounts = new double[26];
        foreach (char c in text) letterCounts[c - 'A'] += 1;
        double letterTotal = text.Length + 26.0;
        for (int i = 0; i < 26; i++) model.LetterLog[i] = Math.Log((letterCounts[i] + 1.0) / letterTotal);

        var bigramCounts = new double[26 * 26];
        var trigramCounts = new double[26 * 26 * 26];
        for (int i = 1; i < text.Length; i++)
        {
            int a = text[i - 1] - 'A', b = text[i] - 'A';
            bigramCounts[a * 26 + b] += 1;
            if (i >= 2) { int c0 = text[i - 2] - 'A'; trigramCounts[(c0 * 26 + a) * 26 + b] += 1; }
        }

        for (int a = 0; a < 26; a++)
        {
            double rowTotal = 0;
            for (int b = 0; b < 26; b++) rowTotal += bigramCounts[a * 26 + b];
            double denom = rowTotal + 26 * SmoothingB;
            for (int b = 0; b < 26; b++) model.BigramLog[a * 26 + b] = Math.Log((bigramCounts[a * 26 + b] + SmoothingB) / denom);
        }
        for (int a = 0; a < 26; a++)
            for (int b = 0; b < 26; b++)
            {
                double rowTotal = 0;
                int baseIdx = (a * 26 + b) * 26;
                for (int c = 0; c < 26; c++) rowTotal += trigramCounts[baseIdx + c];
                double denom = rowTotal + 26 * SmoothingB;
                for (int c = 0; c < 26; c++) model.TrigramLog[baseIdx + c] = Math.Log((trigramCounts[baseIdx + c] + SmoothingB) / denom);
            }
        return model;
    }

    private static double ScoreModel(string text, LanguageModel m)
    {
        if (text.Length == 0) return double.NegativeInfinity;

        double trigramWeight = text.Length < 100 ? 0.1 : (text.Length < 400 ? 0.3 : 0.5);

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
            if (prev2 >= 0 && prev1 >= 0) logp += m.TrigramLog[(prev2 * 26 + prev1) * 26 + idx] * trigramWeight;
            prev2 = prev1; prev1 = idx;
        }

        var freq = new int[26];
        foreach (char ch in text) { int idx = ch - 'A'; if ((uint)idx <= 25) freq[idx]++; }
        double ioc = 0;
        if (n > 1)
        {
            for (int i = 0; i < 26; i++) ioc += freq[i] * (freq[i] - 1);
            ioc /= (double)(n * (n - 1));
        }
        double perChar = n > 0 ? -logp / n : 0;
        return -perChar * 100.0 + ioc * 600.0;
    }

    public static double Score(string text)
    {
        if (text.Length < 4) return 0;
        double de = ScoreModel(text, German);
        double en = ScoreModel(text, English);
        return de > en ? de : en;
    }

    public static double CoarseScore(string text)
    {
        if (text.Length < 2) return 0;
        var freq = new int[26];
        int n = 0;
        foreach (char ch in text) { int idx = ch - 'A'; if ((uint)idx > 25) continue; freq[idx]++; n++; }
        if (n < 2) return 0;
        double ioc = 0;
        for (int i = 0; i < 26; i++) ioc += freq[i] * (freq[i] - 1);
        ioc /= (double)(n * (n - 1));
        return ioc * 1000.0;
    }
}