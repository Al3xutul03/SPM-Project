using EnigmaLogic.Models;
using EnigmaLogic.Models.ChatGpt;
using EnigmaLogic.Services;
using EnigmaLogic.Services.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace ArhivaConvertoarelor.Controllers
{
    public class HomeController : Controller
    {
        private static readonly TimeSpan ChatGptCrackTimeout = TimeSpan.FromSeconds(60);

        private readonly IEnigmaSimService _enigmaService;
        private readonly IEnigmaPredictChatGPTService _chatGptPredictService;

        public HomeController(
            IEnigmaSimService enigmaService,
            IEnigmaPredictChatGPTService chatGptPredictService)
        {
            _enigmaService = enigmaService;
            _chatGptPredictService = chatGptPredictService;
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
        public async Task<IActionResult> DecryptChatGPT([FromBody] DecryptRequest request)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(HttpContext.RequestAborted);
            timeout.CancelAfter(ChatGptCrackTimeout);

            try
            {
                EnigmaCrackResult crackResult = await _chatGptPredictService.CrackAsync(
                    request.Ciphertext ?? string.Empty,
                    cancellationToken: timeout.Token);

                return Json(new
                {
                    plaintext = crackResult.Plaintext,
                    rotor1 = crackResult.Settings.Rotor1.ToString(),
                    rotor2 = crackResult.Settings.Rotor2.ToString(),
                    rotor3 = crackResult.Settings.Rotor3.ToString(),
                    plugboardPairs = crackResult.Settings.PlugboardPairs,
                    leftRotor = crackResult.LeftRotor.ToString(),
                    middleRotor = crackResult.MiddleRotor.ToString(),
                    rightRotor = crackResult.RightRotor.ToString(),
                    fitnessScore = crackResult.FitnessScore,
                    indexOfCoincidence = crackResult.IndexOfCoincidence,
                    evaluatedCandidates = crackResult.EvaluatedCandidates,
                    executionTimeMs = crackResult.ExecutionTime.TotalMilliseconds
                });
            }
            catch (OperationCanceledException)
            {
                return BadRequest(new { error = "Decryption took too long and was stopped." });
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        /// <summary>Decrypts with a known key using the ChatGPT simulation engine.</summary>
        [HttpPost]
        public IActionResult DecryptChatGPTWithKey([FromBody] DecryptWithKeyRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Rotor1) ||
                    string.IsNullOrWhiteSpace(request.Rotor2) ||
                    string.IsNullOrWhiteSpace(request.Rotor3))
                {
                    return BadRequest(new { error = "Choose a letter for all three rotors." });
                }

                if (request.Ciphertext is null || !request.Ciphertext.Any(char.IsAsciiLetter))
                {
                    return BadRequest(new { error = "The ciphertext must contain letters A-Z." });
                }

                var settings = new EnigmaSettings(
                    char.ToUpperInvariant(request.Rotor1.Trim()[0]),
                    char.ToUpperInvariant(request.Rotor2.Trim()[0]),
                    char.ToUpperInvariant(request.Rotor3.Trim()[0]),
                    request.PlugboardPairs ?? []);

                EnigmaOutput output = _chatGptPredictService.Simulate(
                    request.Ciphertext ?? string.Empty,
                    settings);

                return Json(new { plaintext = output.OutputText });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }
    }

    public record DecryptRequest(string? Ciphertext);

    public record DecryptWithKeyRequest(
        string? Ciphertext,
        string? Rotor1,
        string? Rotor2,
        string? Rotor3,
        List<string>? PlugboardPairs
    );

    public record ConvertRequest(
        string? Text,
        string? Rotor1,
        string? Rotor2,
        string? Rotor3,
        List<string>? PlugboardPairs
    );
}
