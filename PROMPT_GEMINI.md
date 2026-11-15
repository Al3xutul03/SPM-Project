Ești un expert în criptografie istorică și arhitect senior C# (.NET 10). Scrie un modul de criptanaliză pentru mașina Enigma din proiectul de mai jos și integrează-l complet în aplicația web. Spune-mi EXACT ce fișiere creez și ce fișiere modific, cu calea completă.

# 1. MEDIUL PROIECTULUI (nu presupune nimic în plus)

- **.NET 10** (`<TargetFramework>net10.0</TargetFramework>`), C# `latest`, `ImplicitUsings` = enable, `Nullable` = enable.
- **Fără pachete NuGet noi.** Doar BCL.
- Soluția: `SPM Project.slnx` (format nou .slnx) cu 3 proiecte:
  - `EnigmaLogic/EnigmaLogic.csproj` – class library (`Microsoft.NET.Sdk`), logica Enigma.
  - `Application/Application.csproj` – ASP.NET Core MVC (`Microsoft.NET.Sdk.Web`), referă `EnigmaLogic`.
  - `Tests/Tests.csproj` – **MSTest.Sdk/4.0.2** (`UseVSTest` = true), referă `EnigmaLogic`. `Tests/MSTestSettings.cs` conține `[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]` → testele rulează în paralel.
- CI (GitHub Actions, ubuntu): `dotnet restore`, `dotnet build --configuration Release`, `dotnet test --configuration Release`. Codul trebuie să compileze FĂRĂ warning-uri noi.
- UI: jQuery 3.6.0 este încărcat în `Views/Shared/_Layout.cshtml`. Paginile de decriptare sunt **partial views** încărcate prin AJAX (`$('#converter-content').html(data)`), deci un `<script>` inline din partial se execută la încărcare.

## Structura EXACTĂ a proiectului (toate fișierele existente)

```
SPM-Project/
├── .github/workflows/ci.yml
├── .dockerignore  .gitattributes  .gitignore
├── SPM Project.slnx
├── debug.ps1  debug.sh
├── Application/
│   ├── Application.csproj
│   ├── Dockerfile
│   ├── Program.cs
│   ├── appsettings.json  appsettings.Development.json
│   ├── Properties/launchSettings.json
│   ├── Controllers/
│   │   ├── FormularController.cs
│   │   └── HomeController.cs
│   ├── Models/ErrorViewModel.cs
│   ├── Views/
│   │   ├── _ViewImports.cshtml  _ViewStart.cshtml
│   │   ├── Formular/FormularIndex.cshtml
│   │   ├── Home/
│   │   │   ├── Index.cshtml  Privacy.cshtml
│   │   │   ├── _Encryption.cshtml
│   │   │   ├── _DecryptionClaude.cshtml
│   │   │   ├── _DecryptionDeepSeek.cshtml
│   │   │   ├── _DecryptionGPT.cshtml
│   │   │   ├── _DecryptionGemini.cshtml      ← pagina ta
│   │   │   └── _DecryptionGrok.cshtml
│   │   └── Shared/
│   │       ├── _Layout.cshtml  _Layout.cshtml.css  _LayoutFormular.cshtml
│   │       ├── _ValidationScriptsPartial.cshtml
│   │       └── Error.cshtml
│   └── wwwroot/  (css/site.css, js/site.js, favicon.ico, lib/...)
├── EnigmaLogic/
│   ├── EnigmaLogic.csproj
│   ├── Models/
│   │   ├── EnigmaOutput.cs
│   │   └── EnigmaSettings.cs
│   └── Services/
│       ├── EnigmaSimService.cs
│       └── Abstractions/IEnigmaSimService.cs
└── Tests/
    ├── Tests.csproj
    ├── MSTestSettings.cs
    └── EnigmaSimServiceTests.cs
```

# 2. CONTRACTE EXISTENTE (NU le modifica, NU le redefini, NU le copia în fișierele tale)

`EnigmaLogic/Models/EnigmaSettings.cs`:
```csharp
namespace EnigmaLogic.Models;

/// Simplified setup: standard rotors I, II, III (ring settings 'A') and Reflector B.
public record EnigmaSettings(
    char Rotor1,   // poziția inițială a rotorului stâng ('A'–'Z')
    char Rotor2,   // poziția inițială a rotorului din mijloc
    char Rotor3,   // poziția inițială a rotorului drept
    IReadOnlyList<string> PlugboardPairs   // ex. ["AB", "CD"]
);
```

`EnigmaLogic/Models/EnigmaOutput.cs`:
```csharp
namespace EnigmaLogic.Models;

public record EnigmaOutput(
    string OutputText,
    (char Left, char Middle, char Right) FinalRotorPositions
);
```

`EnigmaLogic/Services/Abstractions/IEnigmaSimService.cs`:
```csharp
using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions;

public interface IEnigmaSimService
{
    void Configure(EnigmaSettings? settings = null, bool RandomSettings = true);
    string Process(string? inputText = null);
    bool IsCorrect(string expectedInput, EnigmaSettings expectedSettings);
}
```

`EnigmaLogic/Services/EnigmaSimService.cs` (namespace `EnigmaLogic.Services`, implementată de colegi, NU o modifica). Ce trebuie să știi despre ea:
- Mașina este FIXĂ: rotoare **I (stânga), II (mijloc), III (dreapta)**, inele **AAA**, reflector **UKW-B**. Variabile sunt doar cele 3 poziții inițiale și plugboard-ul. Cablaje: I `EKMFLGDQVZNTOWYHXUSPAIBRCJ` (notch Q), II `AJDKSIRUXBLHWTMCQGZNPYFVOE` (notch E), III `BDFHJLCPRTXVZNYEIWGAKMUSQO` (notch V), UKW-B `YRUHQSLDPXNGOKMIEBFZCWVJAT`.
- Pasul se face înainte de criptare, cu double-stepping.
- `Configure(settings, RandomSettings: false)` folosește setările date; `RandomSettings: true` generează poziții aleatoare + **10 perechi** de plugboard.
- **ATENȚIE:** `Process(null)` sau `Process("")` / whitespace NU returnează gol: criptează un text-exemplu ALEATOR (12–22 litere). Nu apela niciodată `Process` cu text gol.
- Proprietate publică `EnigmaSettings? CurrentSettings`.
- Este înregistrată ca **Singleton** în DI și folosită de pagina Encryption → NU o reconfigura din codul tău; creează o instanță nouă `new EnigmaSimService()` când ai nevoie de ea.

# 3. CE TREBUIE SĂ LIVREZI (exact aceste fișiere, nimic altceva)

| # | Acțiune | Cale |
|---|---|---|
| 1 | CREEAZĂ | `EnigmaLogic/Services/Abstractions/IEnigmaPredictGeminiService.cs` |
| 2 | CREEAZĂ | `EnigmaLogic/Services/Cryptography/EnigmaPredictGeminiService.cs` (folderul `Cryptography` nu există încă) |
| 3 | MODIFICĂ | `Application/Program.cs` |
| 4 | MODIFICĂ | `Application/Controllers/HomeController.cs` |
| 5 | ÎNLOCUIEȘTE | `Application/Views/Home/_DecryptionGemini.cshtml` |
| 6 | CREEAZĂ | `Tests/EnigmaPredictGeminiServiceTests.cs` |

Nu atinge alte fișiere (în special nu `.csproj`, `EnigmaSimService.cs`, `IEnigmaSimService.cs`, modelele sau celelalte pagini de decriptare).

## 3.1 Interfața (fișier 1)
```csharp
using EnigmaLogic.Models;

namespace EnigmaLogic.Services.Abstractions;

public interface IEnigmaPredictGeminiService
{
    /// Rulează atacul de criptanaliză pe textul cifrat și returnează setările cele mai probabile.
    Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default);
}
```

## 3.2 Serviciul (fișier 2) – namespace `EnigmaLogic.Services.Cryptography`
Clasa: `public sealed class EnigmaPredictGeminiService : IEnigmaPredictGeminiService`, cu constructor fără parametri (sau cu un parametru opțional de opțiuni) ca să poată fi înregistrată ca Singleton.

**Mecanica Enigma (prioritate maximă):** implementează intern aceeași mașină ca `EnigmaSimService` (I-II-III, inele AAA, UKW-B), cu tabele de lookup precalculate (forward + inverse) și double-stepping exact. Pasul se face ÎNAINTE de trecerea semnalului. Sanitizare: majuscule, elimină tot ce nu e A–Z. Plugboard: perechi reciproce, fără litere duplicate.

**Algoritmul de criptanaliză** (spațiul de chei: 26³ = 17.576 poziții × plugboard):
1. **Etapa 1 – poziții:** pentru fiecare din cele 17.576 poziții de start, decriptează fără plugboard și calculează Index of Coincidence; păstrează top-N candidați. `Parallel.For` cu `ParallelOptions.CancellationToken`. Precalculează un tabel `byte[17576 * 26]` cu permutarea scramblerului pentru fiecare stare a rotoarelor, ca bucla fierbinte să facă doar lookup-uri.
2. **Etapa 1b – fallback pentru texte scurte:** cu 10 perechi de plugboard și sub ~300 de litere, IC-ul brut nu mai găsește poziția corectă (ajunge pe locul ~3000). Dacă etapele 2–3 nu dau un text plauzibil, refă scanarea dând fiecărei poziții un hill climb scurt pe plugboard (o singură trecere, scor = IC) și ia top-N după acest scor.
3. **Etapa 2 – plugboard:** Hill Climbing pe perechi (adaugă / elimină / schimbă partenerul unei perechi; păstrezi doar îmbunătățirile, până la optim local), maxim 13 perechi. Întâi cu IC, apoi cu fitness pe tetragrame.
4. **Oprire timpurie:** dacă fitness-ul normalizat al unui candidat depășește un prag (text clar plauzibil), oprește căutarea.
5. **Verificare finală:** decriptează cu `new EnigmaSimService()` configurat cu setările găsite și verifică faptul că rezultatul e identic cu cel din simularea ta internă; altfel aruncă `InvalidOperationException`.
6. Returnează `EnigmaSettings(Rotor1, Rotor2, Rotor3, PlugboardPairs)` cu perechile în format `"AB"` (litera mai mică prima).

**Model lingvistic:** fitness = media log-probabilităților tetragramelor, tabel `float[26⁴]` indexat `a*17576 + b*676 + c*26 + d`. Nu există fișier de tetragrame în proiect și nu adaug unul: construiește modelul la pornire (lazy, `static`) dintr-un **text de antrenare scris de tine în cod** (`const string`, câteva paragrafe originale în **engleză și germană**, fără umlaute: `ae/oe/ue/ss`). Folosește interpolare (tetragramă/trigramă/bigramă/unigramă) ca tetragramele nevăzute să nu dea `-∞`. Scorează cu ambele limbi și păstrează-l pe cel mai bun. Opțional poți oferi și `LoadTetragrams(Stream)` pentru fișiere `TETRAGRAMA,count`, dar serviciul trebuie să funcționeze fără el.

**Validare și asincronism:**
- `CrackAsync` = `Task.Run(...)` + `Parallel.For`; verifică `cancellationToken` periodic (și în hill climbing) și aruncă `OperationCanceledException` la anulare.
- Aruncă `ArgumentException` dacă textul are sub 4 litere A–Z după sanitizare. Pentru texte scurte NU arunca: încearcă oricum (utilizatorul vrea un răspuns), dar documentează în XML doc că sub ~150 de litere cu 10 perechi rezultatul poate fi greșit.
- Performanță: `Span<T>`, `stackalloc`, tabele `int[]`/`byte[]`, fără alocări în bucla fierbinte. Ținta: un mesaj de ~250 de litere cu 10 perechi spart în sub 20 s în Debug.

## 3.3 `Application/Program.cs` (fișier 3) – conținutul actual COMPLET:
```csharp
using EnigmaLogic.Services;
using EnigmaLogic.Services.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddSingleton<IEnigmaSimService, EnigmaSimService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
```
Adaugă `using EnigmaLogic.Services.Cryptography;` și, imediat sub linia cu `IEnigmaSimService`, `builder.Services.AddSingleton<IEnigmaPredictGeminiService, EnigmaPredictGeminiService>();`. Restul rămâne neschimbat.

## 3.4 `Application/Controllers/HomeController.cs` (fișier 4) – conținutul actual COMPLET:
```csharp
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
```
Modificări (păstrează tot ce există, inclusiv namespace-ul `ArhivaConvertoarelor.Controllers` și acțiunea `Convert`):
- Injectează `IEnigmaPredictGeminiService` în constructor, lângă `IEnigmaSimService`.
- Adaugă acțiunea `[HttpPost] public async Task<IActionResult> DecryptGemini([FromBody] GeminiDecryptRequest request)`:
  - token = `CancellationTokenSource.CreateLinkedTokenSource(HttpContext.RequestAborted)` + `CancelAfter(60 s)`;
  - apelează `CrackAsync`, apoi decriptează cu un `new EnigmaSimService()` (NU cu `_enigmaService`!) configurat cu setările găsite;
  - succes → `Json(new { plaintext, rotor1, rotor2, rotor3, plugboardPairs })` (rotoarele ca string de o literă);
  - `OperationCanceledException` → `BadRequest(new { error = "Decryption took too long and was stopped." })`;
  - `ArgumentException` → `BadRequest(new { error = ex.Message })`.
- Adaugă `public record GeminiDecryptRequest(string? Ciphertext);` în același fișier, lângă `ConvertRequest`. (Nu folosi numele `DecryptRequest`: alți colegi îl pot adăuga în același fișier.)

## 3.5 `Application/Views/Home/_DecryptionGemini.cshtml` (fișier 5) – conținutul actual COMPLET:
```html
<h2 class="converter-title">DECRYPTION GEMINI</h2>

<div class="colleague-workspace">
    <section class="card lt-converter" aria-label="Formular Decryption Gemini">
        <!-- Caseta pentru textul codificat (Input) -->
        <div class="lt-row" style="margin-bottom: 20px;">
            <div class="lt-field" style="width: 100%;">
                <label for="lt-ciphertext-gemini">Ciphertext</label>
                <textarea id="lt-ciphertext-gemini" rows="5" placeholder="Enter the cipher here..."></textarea>
            </div>
        </div>

        <!-- Butonul de conversie -->
        <div style="text-align: center; margin-bottom: 20px;">
            <button type="button" class="lt-button">DECODE</button>
        </div>

        <!-- Caseta pentru textul decodificat (Output) -->
        <div class="lt-row">
            <div class="lt-field" style="width: 100%;">
                <label for="lt-plaintext-gemini">Plaintext</label>
                <textarea id="lt-plaintext-gemini" rows="5" placeholder="The plaintext will appear here..." readonly style="background-color: #f9f6f0;"></textarea>
            </div>
        </div>
    </section>
</div>
```
Păstrează markup-ul, clasele CSS și id-urile existente. Adaugă:
- `id="lt-decode-gemini"` pe buton;
- un `<p id="lt-settings-gemini">` (ascuns inițial) sub Plaintext, pentru cheia găsită: `Rotors: M O H | Plugboard: AI ES HX`;
- un `<script>` inline cu jQuery, încapsulat într-un IIFE: la click → `POST /Home/DecryptGemini` cu JSON `{ ciphertext }`, butonul devine disabled cu textul `DECODING...`, la succes scrie `plaintext` în `#lt-plaintext-gemini` și afișează cheia, la eroare scrie `Error: <mesaj>` în caseta Plaintext, la final reactivează butonul.

## 3.6 Teste (fișier 6) – `Tests/EnigmaPredictGeminiServiceTests.cs`, namespace `Tests`
MSTest 4 (`[TestClass]`, `[TestMethod]`, `Assert.ThrowsExactlyAsync<T>`, `Assert.ThrowsAsync<T>`, `CollectionAssert.AreEquivalent`). Testele rulează în paralel: nu folosi stare statică mutabilă. Minim:
1. Text fără litere (`"123 !?"`) → `ArgumentException`.
2. Text german de ~600 de litere (scris de tine, DIFERIT de textul de antrenare din serviciu), criptat cu `EnigmaSimService` cu poziții `K D T` și 10 perechi → `CrackAsync` returnează exact pozițiile și perechile.
3. Același lucru pe primele ~240 de litere, poziții `M C K`, perechi `AZ BX CW DV EU FT GS HR IQ JP`.
4. Token anulat după 50 ms → `OperationCanceledException`.
5. Simularea ta internă dă exact același text ca `EnigmaSimService` pentru aceleași setări.

# 4. FORMAT DE OUTPUT
- Pentru FIECARE din cele 6 fișiere: un titlu cu **calea exactă** și acțiunea (CREEAZĂ / ÎNLOCUIEȘTE), urmat de **conținutul COMPLET al fișierului** într-un singur bloc de cod. Și pentru fișierele modificate dai fișierul întreg, gata de copiat peste cel vechi.
- Fără `// ... restul codului`, fără fragmente.
- Explicațiile matematice (IC, Hill Climbing, fitness pe tetragrame, double-stepping) le scrii ca scurte comentarii `//` în cod, deasupra metodelor relevante. Fără alt text în afară de titlurile fișierelor.

# 5. AUTOVERIFICARE ÎNAINTE DE RĂSPUNS
- [ ] Double-stepping, start `ADU`, după fiecare tastă: `ADV → AEW → BFX → BFY`.
- [ ] Vector de test: start `AAA`, fără plugboard: `AAAAA` → `BDZGO`.
- [ ] Criptarea e reciprocă și nicio literă nu se mapează pe ea însăși.
- [ ] Nu ai redefinit `EnigmaSettings`, `EnigmaOutput`, `IEnigmaSimService` sau `EnigmaSimService`.
- [ ] Namespace-urile sunt exact: `EnigmaLogic.Services.Abstractions`, `EnigmaLogic.Services.Cryptography`, `ArhivaConvertoarelor.Controllers`, `Tests`.
- [ ] Nu apelezi `EnigmaSimService.Process` cu text gol.
- [ ] Compilează pe `net10.0` fără pachete NuGet noi și fără warning-uri noi.
