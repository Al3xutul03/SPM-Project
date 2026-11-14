using EnigmaLogic.Models;
using EnigmaLogic.Services;

namespace Tests.EvaluationHarness;

/// <summary>
/// Generates reproducible ground-truth benchmark datasets encrypted with the reference
/// <see cref="EnigmaSimService"/> implementation under known settings, plus standard
/// robustness edge-case inputs.
/// </summary>
public static class GroundTruthDatasetGenerator
{
    /// <summary>
    /// Standard benchmark dataset of known plaintexts encrypted under diverse Enigma settings
    /// (varying starting positions and 0 to 10 plugboard pairs).
    /// </summary>
    public static IReadOnlyList<GroundTruthCase> CreateStandardBenchmarkSuite()
    {
        var sim = new EnigmaSimService();
        var specs = new (string Id, string Plaintext, EnigmaSettings Settings)[]
        {
            (
                "GT-01-NoPlugboard-Short",
                "WETTERBERICHTKLAR",
                new EnigmaSettings('A', 'A', 'A', [])
            ),
            (
                "GT-02-TwoSteckers-Tactical",
                "ATTACKATDAWNREINFORCEMENTSARRIVING",
                new EnigmaSettings('B', 'E', 'T', ["AB", "CD"])
            ),
            (
                "GT-03-FiveSteckers-DoubleStep",
                "BLETCHLEYPARKOPERATIONALINTELLIGENCEREPORT",
                new EnigmaSettings('A', 'D', 'V', ["AE", "BF", "CM", "DQ", "HU"])
            ),
            (
                "GT-04-TenSteckers-LongMessage",
                "OPERATIONOVERLORDWEATHERFORECASTFORTHEENGLISHCHANNELISCLEARANDFAVORABLEFORALLIEDLANDINGSATNORMANDY",
                new EnigmaSettings('M', 'E', 'K', ["AN", "EZ", "HK", "IJ", "LR", "MQ", "OT", "PV", "SW", "UX"])
            ),
            (
                "GT-05-TenSteckers-StandardReport",
                "NOTHINGTOREPORTFROMTHEEASTERNSECTORALLUNITSAREHOLDINGTHEIRDESIGNATEDDEFENSIVEPOSITIONS",
                new EnigmaSettings('Q', 'W', 'E', ["AB", "CD", "EF", "GH", "IJ", "KL", "MN", "OP", "QR", "ST"])
            )
        };

        var dataset = new List<GroundTruthCase>(specs.Length);
        foreach (var (id, plaintext, settings) in specs)
        {
            sim.Configure(settings, RandomSettings: false);
            string ciphertext = sim.Process(plaintext);
            string normalizedPlaintext = sim.LastInput!;

            dataset.Add(new GroundTruthCase(
                Id: id,
                Plaintext: normalizedPlaintext,
                Ciphertext: ciphertext,
                Settings: settings,
                RotorOrder: ("I", "II", "III"),
                RingSettings: ('A', 'A', 'A')
            ));
        }

        return dataset;
    }

    /// <summary>
    /// Unusual / edge-case inputs used to evaluate the Robustness metric:
    /// empty strings, whitespace, very short ciphertexts, non-letter characters, and mixed formatting.
    /// </summary>
    public static IReadOnlyList<(string CaseName, string? CiphertextInput, bool ExpectGracefulResultOrArgumentException)> GetEdgeCaseInputs() =>
    [
        ("EmptyString", "", true),
        ("WhitespaceOnly", "   \t\r\n  ", true),
        ("SingleCharacter", "A", true),
        ("VeryShortCiphertext_4Chars", "BDZG", true),
        ("NonLetterCharactersOnly", "1234567890!@#$%^&*()-_=+[]{}", true),
        ("CiphertextWithEmbeddedSymbolsAndSpaces", "B D Z G O ! @ # 1 2 3 X Y Z", true),
        ("LowerCaseInput", "bdzgookmflgdqvzntowyhxuspaibrcj", true)
    ];
}
