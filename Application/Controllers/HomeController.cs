using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace ArhivaConvertoarelor.Controllers
{
    public class HomeController : Controller
    {
        private readonly IEnigmaSimService _enigmaService;

        public HomeController(IEnigmaSimService enigmaService)
        {
            _enigmaService = enigmaService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult GetConverterPage(string page)
        {
            return page switch
            {
                "Encryption" => PartialView("_Encryption"),
                "DecryptionGrok" => PartialView("_DecryptionGrok"),
                "DecryptionGemini" => PartialView("_DecryptionGemini"),
                "DecryptionGPT" => PartialView("_DecryptionGPT"),
                "DecryptionClaude" => PartialView("_DecryptionClaude"),
                "DecryptionDeepSeek" => PartialView("_DecryptionDeepSeek"),
                _ => PartialView("_Encryption")
            };
        }

        [HttpPost]
        public IActionResult Convert([FromBody] ConvertRequest request)
        {
            try
            {
                bool hasCustomRotors =
                    !string.IsNullOrWhiteSpace(request.Rotor1) &&
                    !string.IsNullOrWhiteSpace(request.Rotor2) &&
                    !string.IsNullOrWhiteSpace(request.Rotor3);

                if (hasCustomRotors)
                {
                    var settings = new EnigmaSettings(
                        char.ToUpperInvariant(request.Rotor1!.Trim()[0]),
                        char.ToUpperInvariant(request.Rotor2!.Trim()[0]),
                        char.ToUpperInvariant(request.Rotor3!.Trim()[0]),
                        request.PlugboardPairs ?? []
                    );
                    _enigmaService.Configure(settings, RandomSettings: false);
                }
                else
                {
                    _enigmaService.Configure(null, RandomSettings: true);
                }

                string output = _enigmaService.Process(request.Text);
                var currentSettings = (_enigmaService as EnigmaSimService)?.CurrentSettings;

                return Json(new
                {
                    output,
                    rotor1 = currentSettings?.Rotor1.ToString() ?? "",
                    rotor2 = currentSettings?.Rotor2.ToString() ?? "",
                    rotor3 = currentSettings?.Rotor3.ToString() ?? "",
                    plugboardPairs = currentSettings?.PlugboardPairs ?? []
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }
    }

    public record ConvertRequest(
        string? Text,
        string? Rotor1,
        string? Rotor2,
        string? Rotor3,
        List<string>? PlugboardPairs
    );
}
