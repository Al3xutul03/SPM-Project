// FILE: EnigmaWeb/Controllers/EnigmaDeepSeekController.cs
using System; 
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc; 
using EnigmaLogic.Services;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaWeb.Controllers;

public class EnigmaDeepSeekController : Controller
{
    private readonly IEnigmaPredictServiceDeepSeek _deepSeek;

    public EnigmaDeepSeekController(IEnigmaPredictServiceDeepSeek deepSeek)
    {
        _deepSeek = deepSeek;
    }

    [HttpGet]
    public IActionResult Index() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Decode([FromForm] string? ciphertext, CancellationToken ct)
    {
        var clean = EnigmaMachineDeepSeek.Sanitize(ciphertext);
        if (clean.Length == 0)
            return BadRequest("No A-Z characters found in input.");

        try
        {
            var settings = await _deepSeek.CrackAsync(clean, ct);

            var engine = new EnigmaServiceDeepSeek();
            engine.Configure(settings, RandomSettings: false);
            var output = engine.Process(clean);

            var pairs = settings.PlugboardPairs.Count == 0
            ? "(none)"
            : string.Join(" ", settings.PlugboardPairs);

            return Json(new
            {
                plaintext = output.OutputText,
                settings = new
                {
                    rotors = $"{settings.LeftRotor.RotorName}{settings.MiddleRotor.RotorName}{settings.RightRotor.RotorName}",
                    rings = $"{settings.LeftRotor.RingSetting}{settings.MiddleRotor.RingSetting}{settings.RightRotor.RingSetting}",
                    positions = $"{settings.LeftRotor.InitialPosition}{settings.MiddleRotor.InitialPosition}{settings.RightRotor.InitialPosition}",
                    reflector = settings.Reflector,
                    plugboard = pairs
                }
            });
        }
        catch (OperationCanceledException)
        {
            return StatusCode(499, "Operation cancelled.");
        }
        catch (Exception ex)
        {
            return StatusCode(500, ex.Message);
        }
    }
}