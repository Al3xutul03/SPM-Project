// FILE: EnigmaLogic/Services/EnigmaSimServiceDeepSeek.cs
using EnigmaLogic.Models; using EnigmaLogic.Services.Abstractions;


namespace EnigmaLogic.Services;

public sealed class EnigmaSimServiceDeepSeek : IEnigmaSimServiceDeepSeek
{
    private readonly EnigmaServiceDeepSeek _inner = new();

    public string InputText { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;

    public void Configure(EnigmaSettingsDeepSeek? settings = null, bool RandomSettings = true)
    => _inner.Configure(settings, RandomSettings);

    public string Process() => _inner.Process(EnigmaMachineDeepSeek.Sanitize(InputText)).OutputText;

    public bool IsCorrect(string expectedInput)
    {
        var guess = _inner.Process(EnigmaMachineDeepSeek.Sanitize(expectedInput)).OutputText;
        return guess == EnigmaMachineDeepSeek.Sanitize(Ciphertext);
    }
}