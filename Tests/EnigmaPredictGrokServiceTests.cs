using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Cryptography;

namespace Tests;

[TestClass]
public class EnigmaPredictGrokServiceTests
{
    private const string GermanText =
        "Heute frueh hat die Vorhut den Bergpass erreicht ohne auf nennenswerten Widerstand zu stossen. " +
        "Pioniere reparieren die zerstoerte Holzbruecke am Kilometerstein vierzig. Gefangene sagen aus dass der Gegner " +
        "seine Reserven hinter den Sumpf zurueckgezogen hat. Erbitte Weisung ob der Vormarsch morgen fortgesetzt werden soll. " +
        "Gegen Mittag erschien ueber dem Tal ein einzelner Aufklaerer, der nach kurzer Zeit wieder abdrehte. Sanitaeter versorgen " +
        "zwoelf Verwundete im Schulgebaeude, die Ambulanz wird dringend benoetigt. Die Feldkueche steht hinter der Muehle. " +
        "Spaehtrupps melden Bewegungen schwerer Kolonnen auf der Rollbahn, vermutlich Geschuetze und Pferdewagen. Der Oberst " +
        "wuenscht bis zwanzig Uhr eine genaue Skizze aller Minenfelder.";

    [TestMethod]
    public async Task CrackAsync_TextWithoutLetters_ThrowsArgumentException()
    {
        var service = new EnigmaPredictGrokService();

        await Assert.ThrowsExactlyAsync<ArgumentException>(() => service.CrackAsync("123 !?"));
    }

    [TestMethod]
    public async Task CrackAsync_LongMessage_RecoversSettings()
    {
        string[] plugs = ["AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"];
        var settings = new EnigmaSettings('K', 'D', 'T', plugs);
        var simulator = new EnigmaSimService();
        simulator.Configure(settings, RandomSettings: false);
        string cipher = simulator.Process(GermanText);

        EnigmaSettings found = await new EnigmaPredictGrokService().CrackAsync(cipher);

        Assert.IsNotNull(found);
    }

    [TestMethod]
    public async Task Robustness_CancelledToken_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(5));
        var service = new EnigmaPredictGrokService();

        await Assert.ThrowsAsync<OperationCanceledException>(() => service.CrackAsync(GermanText, cts.Token));
    }
}