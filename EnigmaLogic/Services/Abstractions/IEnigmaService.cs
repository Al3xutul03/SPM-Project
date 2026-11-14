using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions;

public interface IEnigmaService
{
    void Configure(EnigmaSettings? settings = null, bool RandomSettings = true);
    EnigmaOutput Process(string inputText);
}
