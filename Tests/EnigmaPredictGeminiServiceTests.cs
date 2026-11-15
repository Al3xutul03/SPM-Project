using Microsoft.VisualStudio.TestTools.UnitTesting;
using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Cryptography;

namespace Tests;

[TestClass]
public class EnigmaPredictGeminiServiceTests
{
    [TestMethod]
    public async Task CrackAsync_ThrowsArgumentException_OnInvalidText()
    {
        var service = new EnigmaPredictGeminiService();
        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            await service.CrackAsync("123 !?");
        });
    }

    [TestMethod]
    public async Task CrackAsync_RecoversSettings_Successfully()
    {
        // Generare text de test criptat cu EnigmaSimService
        var originalSettings = new EnigmaSettings('M', 'C', 'K', ["AZ", "BX"]);
        var sim = new EnigmaSimService();
        sim.Configure(originalSettings, RandomSettings: false);

        string plaintext = "DIESISTEINBEISPIELFUEREINENKRYPTANALYSETESTDERENIGMAMASCHINEUNDSOFORT";
        string ciphertext = sim.Process(plaintext);

        var cracker = new EnigmaPredictGeminiService();
        var foundSettings = await cracker.CrackAsync(ciphertext);

        Assert.IsNotNull(foundSettings);
        Assert.AreEqual(originalSettings.Rotor1, foundSettings.Rotor1);
        Assert.AreEqual(originalSettings.Rotor2, foundSettings.Rotor2);
        Assert.AreEqual(originalSettings.Rotor3, foundSettings.Rotor3);
    }

    [TestMethod]
    public async Task CrackAsync_RespectsCancellationToken()
    {
        var cracker = new EnigmaPredictGeminiService();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
        {
            await cracker.CrackAsync("DIESISTEINTESTTEXTFUERCIPHERTEXT", cts.Token);
        });
    }

    [TestMethod]
    public void InternalSimulation_MatchesExpectedBehavior()
    {
        var settings = new EnigmaSettings('A', 'A', 'A', []);
        var sim = new EnigmaSimService();
        sim.Configure(settings, RandomSettings: false);

        string output1 = sim.Process("AAAAA");
        Assert.AreEqual("BDZGO", output1);
    }
}