using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Cryptography;

namespace Tests;

[TestClass]
public class EnigmaPredictClaudeServiceTests
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
        var machine = new EnigmaClaudeMachine();
        machine.Configure(new EnigmaSettings('A', 'A', 'A', []));

        Assert.AreEqual("BDZGO", machine.Process("AAAAA").OutputText);
    }

    [TestMethod]
    public void Machine_MiddleRotorOnNotch_DoubleSteps()
    {
        var machine = new EnigmaClaudeMachine();
        machine.Configure(new EnigmaSettings('A', 'D', 'U', []));

        EnigmaOutput output = machine.Process("AAAA");

        Assert.AreEqual(('B', 'F', 'Y'), output.FinalRotorPositions);
    }

    [TestMethod]
    public void Machine_Trace_MatchesProcessStepByStep()
    {
        var settings = new EnigmaSettings('A', 'D', 'U', []);
        var machine = new EnigmaClaudeMachine();
        machine.Configure(settings);

        IReadOnlyList<EnigmaStepState> steps = machine.Trace("aa a!a");

        Assert.HasCount(4, steps);
        Assert.AreEqual(('A', 'D', 'V'), steps[0].RotorPositions);
        Assert.AreEqual(('A', 'E', 'W'), steps[1].RotorPositions);
        Assert.AreEqual(('B', 'F', 'X'), steps[2].RotorPositions);
        Assert.AreEqual(('B', 'F', 'Y'), steps[3].RotorPositions);
        Assert.IsTrue(steps.All(s => s.InputChar == 'A'));

        var reference = new EnigmaClaudeMachine();
        reference.Configure(settings);
        Assert.AreEqual(reference.Process("AAAA").OutputText, new string(steps.Select(s => s.OutputChar).ToArray()));
    }

    [TestMethod]
    public void Machine_Barbarossa1941_DecryptsHistoricalMessage()
    {
        var machine = new EnigmaClaudeMachine();
        machine.Configure(FullKey("II", "IV", "V", "BUL", "BLA", "AV", "BS", "CG", "DL", "FU", "HZ", "IN", "KM", "OW", "RX"));

        string plain = machine.Process("EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM YLKLT TDEIS").OutputText;

        StringAssert.StartsWith(plain, "AUFKLXABTEILUNGXVONXKURTINOWA");
    }

    [TestMethod]
    public void Machine_SameSettings_MatchesEnigmaSimService()
    {
        var settings = new EnigmaSettings('Q', 'E', 'V', ["AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"]);
        var simulator = new EnigmaSimService();
        simulator.Configure(settings, RandomSettings: false);
        var machine = new EnigmaClaudeMachine();
        machine.Configure(settings);

        Assert.AreEqual(simulator.Process(GermanText), machine.Process(GermanText).OutputText);
    }

    [TestMethod]
    public async Task CrackAsync_TextWithoutLetters_ThrowsArgumentException()
    {
        var service = new EnigmaPredictClaudeService();

        await Assert.ThrowsExactlyAsync<ArgumentException>(() => service.CrackAsync("123 !?"));
    }

    [TestMethod]
    public async Task CrackAsync_LongMessageWithTenPlugs_RecoversSettings()
    {
        string[] plugs = ["AQ", "BY", "CU", "DK", "EP", "FT", "GW", "HN", "IX", "LR"];
        var settings = new EnigmaSettings('K', 'D', 'T', plugs);
        var simulator = new EnigmaSimService();
        simulator.Configure(settings, RandomSettings: false);
        string cipher = simulator.Process(GermanText);

        EnigmaSettings found = await new EnigmaPredictClaudeService().CrackAsync(cipher);

        Assert.AreEqual(('K', 'D', 'T'), (found.Rotor1, found.Rotor2, found.Rotor3));
        CollectionAssert.AreEquivalent(plugs, found.PlugboardPairs.ToArray());

        var decoder = new EnigmaClaudeMachine();
        decoder.Configure(found);
        Assert.AreEqual(EnigmaClaudeMachine.Sanitize(GermanText), decoder.Process(cipher).OutputText);
    }

    [TestMethod]
    public async Task CrackAsync_ShortMessageWithTenPlugs_RecoversSettings()
    {
        string[] plugs = ["AZ", "BX", "CW", "DV", "EU", "FT", "GS", "HR", "IQ", "JP"];
        string plain = EnigmaClaudeMachine.Sanitize(GermanText)[..240];
        var simulator = new EnigmaSimService();
        simulator.Configure(new EnigmaSettings('M', 'C', 'K', plugs), RandomSettings: false);
        string cipher = simulator.Process(plain);

        EnigmaSettings found = await new EnigmaPredictClaudeService().CrackAsync(cipher);

        Assert.AreEqual(('M', 'C', 'K'), (found.Rotor1, found.Rotor2, found.Rotor3));
        CollectionAssert.AreEquivalent(plugs, found.PlugboardPairs.ToArray());
    }

    [TestMethod]
    public async Task CrackAsync_CancelledToken_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var service = new EnigmaPredictClaudeService();

        await Assert.ThrowsAsync<OperationCanceledException>(() => service.CrackAsync(GermanText, cts.Token));
    }

    private static EnigmaKey FullKey(string left, string middle, string right, string rings, string positions, params string[] plugs) =>
        new(
            new RotorConfig(left, rings[0], positions[0]),
            new RotorConfig(middle, rings[1], positions[1]),
            new RotorConfig(right, rings[2], positions[2]),
            "B",
            plugs);
}
