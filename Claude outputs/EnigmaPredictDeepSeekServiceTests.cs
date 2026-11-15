using EnigmaLogic.Models;
using EnigmaLogic.Services;
using Tests.EvaluationHarness;

namespace Tests;

[TestClass]
public class EnigmaPredictDeepSeekServiceTests
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
    public void Machine_StandardVector_ProducesKnownCiphertext()
    {
        var machine = new EnigmaServiceDeepSeek();
        machine.Configure(ProjectKey('A', 'A', 'A'), RandomSettings: false);

        Assert.AreEqual("BDZGO", machine.Process("AAAAA").OutputText);
    }

    [TestMethod]
    public void Machine_MiddleRotorOnNotch_DoubleSteps()
    {
        var machine = new EnigmaServiceDeepSeek();
        machine.Configure(ProjectKey('A', 'D', 'U'), RandomSettings: false);

        EnigmaOutputDeepSeek output = machine.Process("AAAA");

        Assert.AreEqual(('B', 'F', 'Y'), output.FinalRotorPositions);
    }

    [TestMethod]
    public void Machine_SameSettingsTwice_IsReciprocal()
    {
        var machine = new EnigmaServiceDeepSeek();
        machine.Configure(ProjectKey('Q', 'E', 'V', "AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"), RandomSettings: false);

        string cipher = machine.Process(GermanText).OutputText;

        Assert.AreEqual(EnigmaMachineDeepSeek.Sanitize(GermanText), machine.Process(cipher).OutputText);
    }

    [TestMethod]
    public void Machine_Barbarossa1941_DecryptsHistoricalMessage()
    {
        var machine = new EnigmaServiceDeepSeek();
        machine.Configure(FullKey("II", "IV", "V", "BUL", "BLA", "AV", "BS", "CG", "DL", "FU", "HZ", "IN", "KM", "OW", "RX"), RandomSettings: false);

        string plain = machine.Process("EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM YLKLT TDEIS").OutputText;

        StringAssert.StartsWith(plain, "AUFKLXABTEILUNGXVONXKURTINOWA");
    }

    [TestMethod]
    public void Machine_SameSettings_MatchesEnigmaSimService()
    {
        var settings = new EnigmaSettings('Q', 'E', 'V', ["AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"]);
        var simulator = new EnigmaSimService();
        simulator.Configure(settings, RandomSettings: false);
        var machine = new EnigmaServiceDeepSeek();
        machine.Configure(DeepSeekCrackCandidate.FromProjectSettings(settings), RandomSettings: false);

        Assert.AreEqual(simulator.Process(GermanText), machine.Process(GermanText).OutputText);
    }

    [TestMethod]
    public async Task CrackAsync_TextWithoutLetters_ThrowsInvalidOperationException()
    {
        var service = new EnigmaPredictServiceDeepSeek();

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => service.CrackAsync("123 !?"));
    }

    [TestMethod]
    public async Task CrackAsync_LongMessageWithTenPlugs_RecoversSettings()
    {
        string[] plugs = ["AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"];
        var settings = new EnigmaSettings('K', 'D', 'T', plugs);
        var simulator = new EnigmaSimService();
        simulator.Configure(settings, RandomSettings: false);
        string cipher = simulator.Process(GermanText);

        EnigmaSettingsDeepSeek found = await new EnigmaPredictServiceDeepSeek().CrackAsync(cipher);

        Assert.AreEqual(("I", "II", "III"), (found.LeftRotor.RotorName, found.MiddleRotor.RotorName, found.RightRotor.RotorName));
        Assert.AreEqual("UKW-B", found.Reflector);
        Assert.AreEqual(('K', 'D', 'T'), (found.LeftRotor.InitialPosition, found.MiddleRotor.InitialPosition, found.RightRotor.InitialPosition));
        CollectionAssert.AreEquivalent(plugs, found.PlugboardPairs.ToArray());

        var decoder = new EnigmaServiceDeepSeek();
        decoder.Configure(found, RandomSettings: false);
        Assert.AreEqual(EnigmaMachineDeepSeek.Sanitize(GermanText), decoder.Process(cipher).OutputText);
    }

    [TestMethod]
    public async Task CrackAsync_ShortMessageWithTenPlugs_RecoversSettings()
    {
        string[] plugs = ["AZ", "BX", "CW", "DV", "EU", "FT", "GS", "HR", "IQ", "JP"];
        string plain = EnigmaMachineDeepSeek.Sanitize(GermanText)[..240];
        var simulator = new EnigmaSimService();
        simulator.Configure(new EnigmaSettings('M', 'C', 'K', plugs), RandomSettings: false);
        string cipher = simulator.Process(plain);

        EnigmaSettingsDeepSeek found = await new EnigmaPredictServiceDeepSeek().CrackAsync(cipher);

        Assert.AreEqual(('M', 'C', 'K'), (found.LeftRotor.InitialPosition, found.MiddleRotor.InitialPosition, found.RightRotor.InitialPosition));
        CollectionAssert.AreEquivalent(plugs, found.PlugboardPairs.ToArray());
    }

    [TestMethod]
    public async Task CrackAsync_CancelledToken_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var service = new EnigmaPredictServiceDeepSeek();

        await Assert.ThrowsAsync<OperationCanceledException>(() => service.CrackAsync(GermanText, cts.Token));
    }

    private static EnigmaSettingsDeepSeek ProjectKey(char left, char middle, char right, params string[] plugs) =>
        DeepSeekCrackCandidate.FromProjectSettings(new EnigmaSettings(left, middle, right, plugs));

    private static EnigmaSettingsDeepSeek FullKey(string left, string middle, string right, string rings, string positions, params string[] plugs) =>
        new(
            new RotorConfigDeepSeek(left, rings[0], positions[0]),
            new RotorConfigDeepSeek(middle, rings[1], positions[1]),
            new RotorConfigDeepSeek(right, rings[2], positions[2]),
            "UKW-B",
            plugs);
}
