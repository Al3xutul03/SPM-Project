using EnigmaLogic.Models;
using EnigmaLogic.Services;

namespace Tests;

[TestClass]
public class EnigmaSimServiceTests
{
    private static EnigmaSettings CreateSampleSettings() => new(
        'A',
        'C',
        'E',
        ["AB", "CD"]
    );

    [TestMethod]
    public void Process_WithoutConfigure_ThrowsInvalidOperationException()
    {
        var service = new EnigmaSimService();

        Assert.ThrowsExactly<InvalidOperationException>(() => service.Process());
    }

    [TestMethod]
    public void IsCorrect_WithoutConfigure_ThrowsInvalidOperationException()
    {
        var service = new EnigmaSimService();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => service.IsCorrect("ATTACKATDAWN", CreateSampleSettings())
        );
    }

    [TestMethod]
    public void IsCorrect_AfterConfigureButWithoutProcess_ThrowsInvalidOperationException()
    {
        var service = new EnigmaSimService();
        service.Configure();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => service.IsCorrect("ATTACKATDAWN", service.CurrentSettings!)
        );
    }

    [TestMethod]
    public void Configure_WithRandomSettings_GeneratesValidEnigmaSettings()
    {
        var service = new EnigmaSimService();

        service.Configure(RandomSettings: true);

        Assert.IsNotNull(service.CurrentSettings);
        var settings = service.CurrentSettings;

        Assert.IsTrue(settings.Rotor1 is >= 'A' and <= 'Z');
        Assert.IsTrue(settings.Rotor2 is >= 'A' and <= 'Z');
        Assert.IsTrue(settings.Rotor3 is >= 'A' and <= 'Z');
        Assert.HasCount(10, settings.PlugboardPairs);
    }

    [TestMethod]
    public void Configure_WithCustomSettings_StoresProvidedSettings()
    {
        var service = new EnigmaSimService();
        var customSettings = CreateSampleSettings();

        service.Configure(customSettings, RandomSettings: false);

        Assert.AreSame(customSettings, service.CurrentSettings);
    }

    [TestMethod]
    public void Configure_WithInvalidRotorLetter_ThrowsArgumentOutOfRangeException()
    {
        var service = new EnigmaSimService();
        var invalidSettings = new EnigmaSettings('1', 'A', 'A', []);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => service.Configure(invalidSettings, RandomSettings: false));
    }

    [TestMethod]
    public void Process_ProducesCiphertextWithNoSelfEncryptedLetters()
    {
        var service = new EnigmaSimService();
        service.Configure(RandomSettings: true);

        string ciphertext = service.Process();

        Assert.IsFalse(string.IsNullOrEmpty(ciphertext));
        Assert.IsNotNull(service.LastInput);
        Assert.AreEqual(service.LastInput.Length, ciphertext.Length);

        // Fundamental Enigma law: a letter can never encrypt to itself
        for (int i = 0; i < ciphertext.Length; i++)
        {
            Assert.AreNotEqual(
                service.LastInput[i],
                ciphertext[i],
                $"Character at index {i} encrypted to itself ('{ciphertext[i]}')."
            );
        }
    }

    [TestMethod]
    public void Process_WithCustomText_MatchesHistoricalEnigmaTestVector()
    {
        // Standard Wehrmacht Enigma I: Rotors I-II-III, Positions A-A-A, Reflector B, no plugboard
        // "AAAAA" -> "BDZGO"
        var service = new EnigmaSimService();
        service.Configure(new EnigmaSettings('A', 'A', 'A', []), RandomSettings: false);

        string output = service.Process("AAAAA");

        Assert.AreEqual("BDZGO", output);
    }

    [TestMethod]
    public void IsCorrect_WithMatchingInputAndSettings_ReturnsTrue()
    {
        var service = new EnigmaSimService();
        var initialSettings = CreateSampleSettings();
        service.Configure(initialSettings, RandomSettings: false);
        _ = service.Process();

        string actualInput = service.LastInput!;

        // Exact instance match
        Assert.IsTrue(service.IsCorrect(actualInput, initialSettings));

        // Equivalent settings with different casing and reversed plugboard pair order
        var equivalentSettings = new EnigmaSettings(
            'a',
            'c',
            'e',
            ["DC", "BA"]
        );
        Assert.IsTrue(service.IsCorrect($"  {actualInput.ToLowerInvariant()}  ", equivalentSettings));
    }

    [TestMethod]
    public void IsCorrect_WithWrongInputAndCorrectSettings_ReturnsFalse()
    {
        var service = new EnigmaSimService();
        service.Configure(RandomSettings: true);
        _ = service.Process();

        Assert.IsFalse(service.IsCorrect("WRONGUESSXYZ", service.CurrentSettings!));
    }

    [TestMethod]
    public void IsCorrect_WithCorrectInputButWrongInitialPosition_ReturnsFalse()
    {
        var service = new EnigmaSimService();
        var initialSettings = CreateSampleSettings();
        service.Configure(initialSettings, RandomSettings: false);
        _ = service.Process();

        var wrongPositionSettings = initialSettings with { Rotor3 = 'Z' };

        Assert.IsFalse(service.IsCorrect(service.LastInput!, wrongPositionSettings));
    }

    [TestMethod]
    public void IsCorrect_WithCorrectInputButWrongPlugboard_ReturnsFalse()
    {
        var service = new EnigmaSimService();
        var initialSettings = CreateSampleSettings();
        service.Configure(initialSettings, RandomSettings: false);
        _ = service.Process();

        var wrongPlugboardSettings = initialSettings with
        {
            PlugboardPairs = ["AB", "EF"]
        };

        Assert.IsFalse(service.IsCorrect(service.LastInput!, wrongPlugboardSettings));
    }

    [TestMethod]
    public void Configure_AfterProcess_ResetsStateAndRequiresProcessAgain()
    {
        var service = new EnigmaSimService();
        service.Configure();
        _ = service.Process();

        // Re-configuring should clear the previous run
        service.Configure();

        Assert.IsNull(service.LastInput);
        Assert.IsNull(service.LastOutput);
        Assert.ThrowsExactly<InvalidOperationException>(
            () => service.IsCorrect("ANYTHING", service.CurrentSettings!)
        );
    }
}
