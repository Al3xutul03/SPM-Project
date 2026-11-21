// EnigmaLogic/Services/Abstractions/IEnigmaInterfacesDeepSeek.cs
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions
{
    public interface IEnigmaServiceDeepSeek
    {
        void Configure(EnigmaSettingsDeepSeek? settings = null, bool RandomSettings = true);
        EnigmaOutputDeepSeek Process(string inputText);
    }

    public interface IEnigmaSimServiceDeepSeek
    {
        void Configure(EnigmaSettingsDeepSeek? settings = null, bool RandomSettings = true);
        string Process();
        bool IsCorrect(string expectedInput);
    }

    public interface IEnigmaPredictServiceDeepSeek
    {
        Task<EnigmaSettingsDeepSeek> CrackAsync(string ciphertext, CancellationToken cancellationToken = default);
    }

    /// <summary>Diagnostic interface used by the test harness, not by CrackAsync.</summary>
    public interface IEnigmaPredictDiagnosticDeepSeek
    {
        Task<CrackDiagnosticDeepSeek> DiagnoseAsync(
            string ciphertext,
            (int L, int M, int R) truePositions,
            IReadOnlyList<string> truePlugboard,
            CancellationToken cancellationToken = default);
    }
}