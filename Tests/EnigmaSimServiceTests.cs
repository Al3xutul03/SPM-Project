using EnigmaLogic.Models;
using EnigmaLogic.Services;

namespace Tests;

[TestClass]
public class EnigmaSimServiceTests
{
    private static EnigmaSettings CreateSampleSettings() => new(
        new RotorConfig("I", 'A', 'A'),
        new RotorConfig("II", 'B', 'C'),
        new RotorConfig("III", 'D', 'E'),
        "B",
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

        // Ensure 3 distinct rotors were chosen
        string[] rotors =
        [
            settings.LeftRotor.RotorName,
            settings.MiddleRotor.RotorName,
            settings.RightRotor.RotorName
        ];
        Assert.AreEqual(3, rotors.Distinct(StringComparer.OrdinalIgnoreCase).Count());

        // Ensure valid reflector and 10 plugboard pairs
        CollectionAssert.Contains(new[] { "B", "C" }, settings.Reflector);
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
    public void Configure_WithInvalidRotorName_ThrowsArgumentException()
    {
        var service = new EnigmaSimService();
        var invalidSettings = new EnigmaSettings(
            new RotorConfig("INVALID", 'A', 'A'),
            new RotorConfig("II", 'A', 'A'),
            new RotorConfig("III", 'A', 'A'),
            "B",
            []
        );

        Assert.ThrowsExactly<ArgumentException>(() => service.Configure(invalidSettings, RandomSettings: false));
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
            new RotorConfig("i", 'a', 'a'),
            new RotorConfig("ii", 'b', 'c'),
            new RotorConfig("iii", 'd', 'e'),
            "b",
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

        var wrongPositionSettings = initialSettings with
        {
            RightRotor = initialSettings.RightRotor with { InitialPosition = 'Z' }
        };

        Assert.IsFalse(service.IsCorrect(service.LastInput!, wrongPositionSettings));
    }

    [TestMethod]
    public void IsCorrect_WithCorrectInputButWrongRotorOrPlugboard_ReturnsFalse()
    {
        var service = new EnigmaSimService();
        var initialSettings = CreateSampleSettings();
        service.Configure(initialSettings, RandomSettings: false);
        _ = service.Process();

        var wrongRotorSettings = initialSettings with
        {
            LeftRotor = initialSettings.LeftRotor with { RotorName = "IV" }
        };
        var wrongPlugboardSettings = initialSettings with
        {
            PlugboardPairs = ["AB", "EF"]
        };

        Assert.IsFalse(service.IsCorrect(service.LastInput!, wrongRotorSettings));
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
