using EnigmaLogic.Models;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace ArhivaConvertoarelor.Controllers
{
    public class HomeController : Controller
    {
        private readonly IEnigmaSimService _enigmaService;
        private readonly IEnigmaPredictGeminiService _geminiPredictService;

        public HomeController(IEnigmaSimService enigmaService, IEnigmaPredictGeminiService geminiPredictService)
        {
            _enigmaService = enigmaService;
            _geminiPredictService = geminiPredictService;
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

        [HttpPost]
        public async Task<IActionResult> DecryptGemini([FromBody] GeminiDecryptRequest request)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(HttpContext.RequestAborted);
                cts.CancelAfter(TimeSpan.FromSeconds(60));

                var settings = await _geminiPredictService.CrackAsync(request.Ciphertext ?? string.Empty, cts.Token);

                // Decriptare efectivă folosind o instanță nouă de EnigmaSimService configurată cu setările prezise
                var decryptor = new EnigmaSimService();
                decryptor.Configure(settings, RandomSettings: false);
                string plaintext = decryptor.Process(request.Ciphertext);

                return Json(new
                {
                    plaintext,
                    rotor1 = settings.Rotor1.ToString(),
                    rotor2 = settings.Rotor2.ToString(),
                    rotor3 = settings.Rotor3.ToString(),
                    plugboardPairs = settings.PlugboardPairs
                });
            }
            catch (OperationCanceledException)
            {
                return BadRequest(new { error = "Decryption took too long and was stopped." });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { error = ex.Message });
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

    public record GeminiDecryptRequest(
        string? Ciphertext
    );
}