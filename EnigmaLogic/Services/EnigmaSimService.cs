using System.Text;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services;

public class EnigmaSimService : IEnigmaSimService
{
    private static readonly Dictionary<string, (string Wiring, char Notch)> RotorDefinitions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["I"]   = ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", 'Q'),
        ["II"]  = ("AJDKSIRUXBLHWTMCQGZNPYFVOE", 'E'),
        ["III"] = ("BDFHJLCPRTXVZNYEIWGAKMUSQO", 'V'),
        ["IV"]  = ("ESOVPZJAYQUIRHXLNFTGKDCMWB", 'J'),
        ["V"]   = ("VZBRGITYUPSDNHLXAWMJQOFECK", 'Z')
    };

    private static readonly Dictionary<string, string> ReflectorDefinitions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["B"] = "YRUHQSLDPXNGOKMIEBFZCWVJAT",
        ["C"] = "FVPJIAOYEDRZXWGCTKUQSBNMHL"
    };

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

    public string Process()
    {
        if (CurrentSettings is null)
        {
            throw new InvalidOperationException("Machine must be configured by calling Configure() before calling Process().");
        }

        LastInput = SamplePlaintexts[Random.Shared.Next(SamplePlaintexts.Length)];
        LastOutput = RunMachine(LastInput, CurrentSettings);

        return LastOutput.OutputText;
    }

    public bool IsCorrect(string expectedInput)
    {
        ArgumentNullException.ThrowIfNull(expectedInput);

        if (LastOutput is null || LastInput is null)
        {
            throw new InvalidOperationException("Process() must be called before calling IsCorrect().");
        }

        string normalizedGuess = NormalizeText(expectedInput);
        return string.Equals(normalizedGuess, LastInput, StringComparison.Ordinal);
    }

    private static EnigmaOutput RunMachine(string inputText, EnigmaSettings settings)
    {
        var (leftWiring, _) = RotorDefinitions[settings.LeftRotor.RotorName];
        var (middleWiring, middleNotch) = RotorDefinitions[settings.MiddleRotor.RotorName];
        var (rightWiring, rightNotch) = RotorDefinitions[settings.RightRotor.RotorName];
        string reflectorWiring = ReflectorDefinitions[settings.Reflector];

        int leftPos = ToIndex(settings.LeftRotor.InitialPosition);
        int middlePos = ToIndex(settings.MiddleRotor.InitialPosition);
        int rightPos = ToIndex(settings.RightRotor.InitialPosition);

        int leftRing = ToIndex(settings.LeftRotor.RingSetting);
        int middleRing = ToIndex(settings.MiddleRotor.RingSetting);
        int rightRing = ToIndex(settings.RightRotor.RingSetting);

        int middleNotchIdx = ToIndex(middleNotch);
        int rightNotchIdx = ToIndex(rightNotch);

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
            signal = PassForward(signal, rightWiring, rightPos, rightRing);
            signal = PassForward(signal, middleWiring, middlePos, middleRing);
            signal = PassForward(signal, leftWiring, leftPos, leftRing);

            // 3. Reflector
            signal = reflectorWiring[signal] - 'A';

            // 4. Left -> Middle -> Right rotors (backward)
            signal = PassBackward(signal, leftWiring, leftPos, leftRing);
            signal = PassBackward(signal, middleWiring, middlePos, middleRing);
            signal = PassBackward(signal, rightWiring, rightPos, rightRing);

            // 5. Plugboard out
            signal = plugboard[signal];

            outputBuilder.Append((char)('A' + signal));
        }

        return new EnigmaOutput(
            outputBuilder.ToString(),
            (ToChar(leftPos), ToChar(middlePos), ToChar(rightPos))
        );
    }

    private static int PassForward(int signal, string wiring, int position, int ringSetting)
    {
        int offset = (position - ringSetting + 26) % 26;
        int contactIn = (signal + offset) % 26;
        int contactOut = wiring[contactIn] - 'A';
        return (contactOut - offset + 26) % 26;
    }

    private static int PassBackward(int signal, string wiring, int position, int ringSetting)
    {
        int offset = (position - ringSetting + 26) % 26;
        int contactIn = (signal + offset) % 26;
        char targetChar = (char)('A' + contactIn);
        int contactOut = wiring.IndexOf(targetChar);
        return (contactOut - offset + 26) % 26;
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
            map[a] = b;
            map[b] = a;
        }

        return map;
    }

    private static EnigmaSettings GenerateRandomSettings()
    {
        var rng = Random.Shared;
        string[] availableRotors = ["I", "II", "III", "IV", "V"];
        rng.Shuffle(availableRotors);

        var left = new RotorConfig(availableRotors[0], RandomLetter(rng), RandomLetter(rng));
        var middle = new RotorConfig(availableRotors[1], RandomLetter(rng), RandomLetter(rng));
        var right = new RotorConfig(availableRotors[2], RandomLetter(rng), RandomLetter(rng));

        string reflector = rng.Next(2) == 0 ? "B" : "C";

        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        rng.Shuffle(alphabet);

        var plugboardPairs = new List<string>(10);
        for (int i = 0; i < 20; i += 2)
        {
            plugboardPairs.Add($"{alphabet[i]}{alphabet[i + 1]}");
        }

        return new EnigmaSettings(left, middle, right, reflector, plugboardPairs);
    }

    private static void ValidateSettings(EnigmaSettings settings)
    {
        ValidateRotor(settings.LeftRotor, nameof(settings.LeftRotor));
        ValidateRotor(settings.MiddleRotor, nameof(settings.MiddleRotor));
        ValidateRotor(settings.RightRotor, nameof(settings.RightRotor));

        if (!ReflectorDefinitions.ContainsKey(settings.Reflector))
        {
            throw new ArgumentException($"Unsupported reflector '{settings.Reflector}'. Valid options: B, C.");
        }

        _ = BuildPlugboardMap(settings.PlugboardPairs);
    }

    private static void ValidateRotor(RotorConfig rotor, string paramName)
    {
        ArgumentNullException.ThrowIfNull(rotor, paramName);

        if (!RotorDefinitions.ContainsKey(rotor.RotorName))
        {
            throw new ArgumentException($"Unsupported rotor '{rotor.RotorName}'. Valid options: I, II, III, IV, V.", paramName);
        }

        _ = ToIndex(rotor.RingSetting);
        _ = ToIndex(rotor.InitialPosition);
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
