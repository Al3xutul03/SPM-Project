using System.Text;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services;

public class EnigmaSimService : IEnigmaSimService
{
    // Standard Wehrmacht Enigma I Rotors I, II, III and Reflector B
    private const string LeftRotorWiring = "EKMFLGDQVZNTOWYHXUSPAIBRCJ";
    private const string MiddleRotorWiring = "AJDKSIRUXBLHWTMCQGZNPYFVOE";
    private const char MiddleRotorNotch = 'E';
    private const string RightRotorWiring = "BDFHJLCPRTXVZNYEIWGAKMUSQO";
    private const char RightRotorNotch = 'V';
    private const string ReflectorBWiring = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

    private static readonly string[] SamplePlaintexts =
    [
        "WETTERBERICHTKLAR",
        "ATTACKATDAWN",
        "ENIGMAMACHINE",
        "BLETCHLEYPARK",
        "SECRETMESSAGE",
        "OPERATIONOVERLORD",
        "REINFORCEMENTSARRIVING",
        "NOTHINGTOREPORT"
    ];

    public EnigmaSettings? CurrentSettings { get; private set; }
    public string? LastInput { get; private set; }
    public EnigmaOutput? LastOutput { get; private set; }

    public void Configure(EnigmaSettings? settings = null, bool RandomSettings = true)
    {
        if (RandomSettings || settings is null)
        {
            CurrentSettings = GenerateRandomSettings();
        }
        else
        {
            ValidateSettings(settings);
            CurrentSettings = settings;
        }

        LastInput = null;
        LastOutput = null;
    }

    public string Process(string? inputText = null)
    {
        if (CurrentSettings is null)
        {
            throw new InvalidOperationException("Machine must be configured by calling Configure() before calling Process().");
        }

        string rawInput = string.IsNullOrWhiteSpace(inputText)
            ? SamplePlaintexts[Random.Shared.Next(SamplePlaintexts.Length)]
            : inputText;

        LastInput = NormalizeText(rawInput);
        LastOutput = RunMachine(LastInput, CurrentSettings);

        return LastOutput.OutputText;
    }

    public bool IsCorrect(string expectedInput, EnigmaSettings expectedSettings)
    {
        ArgumentNullException.ThrowIfNull(expectedInput);
        ArgumentNullException.ThrowIfNull(expectedSettings);

        if (CurrentSettings is null || LastOutput is null || LastInput is null)
        {
            throw new InvalidOperationException("Process() must be called before calling IsCorrect().");
        }

        string normalizedGuess = NormalizeText(expectedInput);
        return string.Equals(normalizedGuess, LastInput, StringComparison.Ordinal)
            && AreSettingsEqual(CurrentSettings, expectedSettings);
    }

    private static bool AreSettingsEqual(EnigmaSettings actual, EnigmaSettings expected)
    {
        if (char.ToUpperInvariant(actual.Rotor1) != char.ToUpperInvariant(expected.Rotor1) ||
            char.ToUpperInvariant(actual.Rotor2) != char.ToUpperInvariant(expected.Rotor2) ||
            char.ToUpperInvariant(actual.Rotor3) != char.ToUpperInvariant(expected.Rotor3))
        {
            return false;
        }

        try
        {
            int[] actualPlugboard = BuildPlugboardMap(actual.PlugboardPairs);
            int[] expectedPlugboard = BuildPlugboardMap(expected.PlugboardPairs);
            return actualPlugboard.AsSpan().SequenceEqual(expectedPlugboard);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static EnigmaOutput RunMachine(string inputText, EnigmaSettings settings)
    {
        int leftPos = ToIndex(settings.Rotor1);
        int middlePos = ToIndex(settings.Rotor2);
        int rightPos = ToIndex(settings.Rotor3);

        int middleNotchIdx = ToIndex(MiddleRotorNotch);
        int rightNotchIdx = ToIndex(RightRotorNotch);

        int[] plugboard = BuildPlugboardMap(settings.PlugboardPairs);

        string normalizedInput = NormalizeText(inputText);
        var outputBuilder = new StringBuilder(normalizedInput.Length);

        foreach (char ch in normalizedInput)
        {
            // Step rotors before signal passes through (including Enigma double-stepping)
            bool middleAtNotch = middlePos == middleNotchIdx;
            bool rightAtNotch = rightPos == rightNotchIdx;

            if (middleAtNotch)
            {
                leftPos = (leftPos + 1) % 26;
                middlePos = (middlePos + 1) % 26;
            }
            else if (rightAtNotch)
            {
                middlePos = (middlePos + 1) % 26;
            }

            rightPos = (rightPos + 1) % 26;

            // Pass current through components
            int signal = ch - 'A';

            // 1. Plugboard in
            signal = plugboard[signal];

            // 2. Right -> Middle -> Left rotors (forward)
            signal = PassForward(signal, RightRotorWiring, rightPos);
            signal = PassForward(signal, MiddleRotorWiring, middlePos);
            signal = PassForward(signal, LeftRotorWiring, leftPos);

            // 3. Reflector B
            signal = ReflectorBWiring[signal] - 'A';

            // 4. Left -> Middle -> Right rotors (backward)
            signal = PassBackward(signal, LeftRotorWiring, leftPos);
            signal = PassBackward(signal, MiddleRotorWiring, middlePos);
            signal = PassBackward(signal, RightRotorWiring, rightPos);

            // 5. Plugboard out
            signal = plugboard[signal];

            outputBuilder.Append((char)('A' + signal));
        }

        return new EnigmaOutput(
            outputBuilder.ToString(),
            (ToChar(leftPos), ToChar(middlePos), ToChar(rightPos))
        );
    }

    private static int PassForward(int signal, string wiring, int position)
    {
        int contactIn = (signal + position) % 26;
        int contactOut = wiring[contactIn] - 'A';
        return (contactOut - position + 26) % 26;
    }

    private static int PassBackward(int signal, string wiring, int position)
    {
        int contactIn = (signal + position) % 26;
        char targetChar = (char)('A' + contactIn);
        int contactOut = wiring.IndexOf(targetChar);
        return (contactOut - position + 26) % 26;
    }

    private static int[] BuildPlugboardMap(IReadOnlyList<string> pairs)
    {
        int[] map = new int[26];
        for (int i = 0; i < 26; i++)
        {
            map[i] = i;
        }

        if (pairs is null)
        {
            return map;
        }

        bool[] used = new bool[26];

        foreach (string rawPair in pairs)
        {
            if (string.IsNullOrWhiteSpace(rawPair))
            {
                continue;
            }

            string pair = NormalizeText(rawPair);
            if (pair.Length != 2)
            {
                throw new ArgumentException($"Invalid plugboard pair '{rawPair}'. Expected 2 letters A-Z.");
            }

            int a = pair[0] - 'A';
            int b = pair[1] - 'A';

            if (a == b)
            {
                continue;
            }

            if ((used[a] && map[a] != b) || (used[b] && map[b] != a))
            {
                throw new ArgumentException($"Conflicting plugboard connection for '{pair}'.");
            }

            map[a] = b;
            map[b] = a;
            used[a] = true;
            used[b] = true;
        }

        return map;
    }

    private static EnigmaSettings GenerateRandomSettings()
    {
        var rng = Random.Shared;

        char rotor1 = RandomLetter(rng);
        char rotor2 = RandomLetter(rng);
        char rotor3 = RandomLetter(rng);

        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        rng.Shuffle(alphabet);

        var plugboardPairs = new List<string>(10);
        for (int i = 0; i < 20; i += 2)
        {
            plugboardPairs.Add($"{alphabet[i]}{alphabet[i + 1]}");
        }

        return new EnigmaSettings(rotor1, rotor2, rotor3, plugboardPairs);
    }

    private static void ValidateSettings(EnigmaSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        _ = ToIndex(settings.Rotor1);
        _ = ToIndex(settings.Rotor2);
        _ = ToIndex(settings.Rotor3);
        _ = BuildPlugboardMap(settings.PlugboardPairs);
    }

    private static string NormalizeText(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            char upper = char.ToUpperInvariant(c);
            if (upper is >= 'A' and <= 'Z')
            {
                sb.Append(upper);
            }
        }
        return sb.ToString();
    }

    private static int ToIndex(char letter)
    {
        char upper = char.ToUpperInvariant(letter);
        if (upper is < 'A' or > 'Z')
        {
            throw new ArgumentOutOfRangeException(nameof(letter), $"Expected a letter A-Z, but got '{letter}'.");
        }
        return upper - 'A';
    }

    private static char ToChar(int index) => (char)('A' + ((index % 26 + 26) % 26));

    private static char RandomLetter(Random rng) => (char)('A' + rng.Next(26));
}
