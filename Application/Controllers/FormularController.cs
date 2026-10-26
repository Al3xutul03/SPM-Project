using Microsoft.AspNetCore.Mvc;

namespace Enigma.Controllers
{
    public class FormularController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}