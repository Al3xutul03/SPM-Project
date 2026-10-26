using Microsoft.AspNetCore.Mvc;

namespace ArhivaConvertoarelor.Controllers
{
    public class HomeController : Controller
    {
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
                "DecryptionPerplexity" => PartialView("_DecryptionPerplexity"),
                _ => PartialView("_Encryption")
            };
        }
    }
}