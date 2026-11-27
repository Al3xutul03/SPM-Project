using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using EnigmaLogic.Models;
using EnigmaLogic.Services.Abstractions;

namespace EnigmaLogic.Services.Cryptography
{
    public sealed class EnigmaPredictGrokService : IEnigmaPredictGrokService
    {
        // ------------------------------------------------------------------
        // Nested result type required by the contract
        // ------------------------------------------------------------------
        public sealed record CrackDetails(
            string[] RotorOrder,
            char[] StartPositions,
            IReadOnlyList<string> PlugboardPairs,
            string Plaintext,
            double Score);

        // ------------------------------------------------------------------
        // Tunable stage sizes / limits
        // ------------------------------------------------------------------
        private const int K1 = 20000;
        private const int K2 = 300;
        private const int M = 5;
        private const int MaxPairs = 10;
        private const int Stage1Len = 200;
        private const int Stage2Len = 150;
        private const double MinGainNgram = 2.0;
        private const double MinGainIoc = 1e-4;
        private const int MaxStage2Pairs = 3;

        // ------------------------------------------------------------------
        // Machine constants (copied literally)
        // ------------------------------------------------------------------
        private static readonly string[] RotorNames = { "I", "II", "III", "IV", "V" };
        private static readonly string[] RotorWirings =
        {
            "EKMFLGDQVZNTOWYHXUSPAIBRCJ", // I
            "AJDKSIRUXBLHWTMCQGZNPYFVOE", // II
            "BDFHJLCPRTXVZNYEIWGAKMUSQO", // III
            "ESOVPZJAYQUIRHXLNFTGKDCMWB", // IV
            "VZBRGITYUPSDNHLXAWMJQOFECK"  // V
        };
        private static readonly char[] NotchLetters = { 'Q', 'E', 'V', 'J', 'Z' };
        private const string ReflectorB = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

        // Pre-computed maps (built in static ctor)
        private static readonly int[][] Fwd = new int[5][];
        private static readonly int[][] Inv = new int[5][];
        private static readonly int[] Notch = new int[5];
        private static readonly int[] Refl = new int[26];

        // N-gram tables
        private static readonly float[] BigramLog = new float[26 * 26];
        private static readonly float[] TrigramLog = new float[26 * 26 * 26];

        // Original generic English training text (≥ 5000 A–Z letters)
        private const string TrainingText =
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENCONTINUESRUNNINGTHROUGHTHEFORESTWHILETHEBIRDS"
            + "SINGINTHEMORNINGLIGHTANDTHEWINDWHISPERSTHROUGHTHELEAVESOFTHETREESCREATINGAMELODYTHATECHOES"
            + "ACROSSTHEVALLEYWHEREFARMERSWORKHARDINTHEFIELDSGROWINGWHEATANDCORNFORTHERHARVESTSEASONTHAT"
            + "COMESAFTERALONGSUMMEROFCAREANDDEDICATIONTOTHELANDOFTHEIRANCESTORSWHOSETTLEDHEREMANY YEARS"
            + "AGOWHENLIFEWASDIFFICULTBUTFULLYOFHOPEANDPROMISEFORTHEFUTUREGENERATIONSTHATWOULDFOLLOWINTHEIR"
            + "FOOTSTEPSANDBUILDASTRONGCOMMUNITYBASEDONTRUSTANDMUTUALRESPECTAMONGALLPEOPLELIVINGINTHIS"
            + "BEAUTIFULREGIONOFTHECOUNTRYWHEREMOUNTAINSRISENEARTHESKYANDRIVERSFLOWGENTLYTOWARDSTHESEA"
            + "CARRYINGWATERESSENTIALFORLIFEANDAGRICULTUREINTHEREGIONSURROUNDINGTHECOASTALCITIESWHERESHIPS"
            + "ARRIVEFROMDISTANTLANDSBRINGINGGOODSANDIDEASTHATENRICHTHECULTUREANDECONOMYOFTHEAREAOVERTIME"
            + "ASNEWTECHNOLOGIESDEVELOPANDSOCIETYADAPTSTOTHECHANGINGNEEDSOFTHEDIGITALAGEWHILEPRESERVING"
            + "IMPORTANTTRADITIONSANDVALUESHANDEDDWONFROMONEGENERATIONTOTHENEXTWITHCAREANDWISDOMTHATONLY"
            + "EXPERIENCECANPROVIDEINTHESUBJECTOFHUMANENDEAVORANDPROGRESSINSCIENCEARTANDPHILOSOPHYTHAT"
            + "GUIDEOURUNDERSTANDINGOFTHEWORLDANDPLACEWITHINITASTHECENTURIESPASSANDHISTORYISWRITTENBYTHOSE"
            + "WHOWITNESSTHEEVENTSOFTHETIMESTHEYINHABITANDRECORDTHEMFORPOSTERITYSO THATFUTURESCHOLARSMAY"
            + "STUDYANDLEARNFROMTHEPASTINORDERTOBUILDABETTERTOMORROWFORALLEVERYONEWHOCOMESAFTERUSINTHIS"
            + "CONTINUOUSCYCLEOFLIFEANDKNOWLEDGETHATDEFINESOURSPECIESANDSETUSAPARTFROMOTHERCREATURESON"
            + "THEPLANETEARTHWHICHISUNIQUEINTHEKNOWNUNIVERSEFORSUPPORTINGCOMPLEXLIFEFORMSANDINTELLIGENT"
            + "BEINGS CAPABLEOFREFLECTIONANDCREATIVITYTHATLEADS TOGREATACHIEVEMENTSINMANYFIELDSINCLUDING"
            + "MATHEMATICSPHYSICSCHEMISTRYBIOLOGYANDTHEHUMANITIESASWELLASENGINEERINGANDTECHNOLOGYTHAT"
            + "IMPROVETHEQUALITYOFLIFEFORBILLIONSOFPEOPLEAROUNDTHEGLOBEEVERYDAYTHROUGHINNOVATIONAND"
            + "COLLABORATIONACROSSBORDERSANDCULTURESINAPROCESSTHATNEVERSTOPSANDALWAYSMOVESFORWARDWITH"
            + "DETERMINATIONANDHOPEFORABRIGHTFUTUREWHERESUSTAINABILITYANDPEACEAREPRIORITIESFORALLNATIONS"
            + "WORKINGTOGETHERTOADDRESSTHECHALLENGESOFTHEMODERNWORLDINCLUDINGCLIMATECHANGEANDRESOURCE"
            + "MANAGEMENTINWAYSTHATBENEFITBOTHPEOPLEANDTHENATURALENVIRONMENTWEDEPENDONFORSURVIVALAND"
            + "WELLBEINGINTHETERRESTRIALECOSYSTEMTHATSUPPORTSOURLIVESANDTHOSEOFCOUNTLESSOTHERSPECIES"
            + "WITHWHOMWESHARETHISPLANETANDMUSTLEARNTOCOEXISTINHARMONYTHROUGHUNDERSTANDINGANDRESPECT"
            + "FORTHEDELICATEBALANCEOFNATURETHATSUSTAINSEVERYTHINGWEKNOWANDVALUEINEXISTENCEITSELFASWE"
            + "CONTINUETOEXPLOREANDDISCOVERNEWASPECTSOFREALITYTHROUGHSCIENCEANDOBSERVATIONTHATREVEAL"
            + "THEUNDERLYINGPRINCIPLESOFTHEUNIVERSEANDHELPUSTOCOMPREHENDOURPLACEWITHINTHESVASTAND"
            + "MYSTERIOUSCOSMOS THATSTRETCHESBEYONDOURCURRENTIMAGINATIONANDUNDERSTANDINGBUTREMAINSA"
            + "SUBJECTOFFASCINATIONANDSTUDYFORGENERATIONSTOCOMEASLONGASHUMANITYEXISTSANDEAGERLYSEEKS"
            + "KNOWLEDGEABOUTTHEWORLDSURROUNDINGITANDTHEFORCESTHATSHAPETHEEVENTSWEEXPERIENCEINDAILYLIFE"
            + "ANDHISTORICALCONTEXTSTHATINFLUENCEOURSOCIETIESANDINDIVIDUALDESTINIESINPROFOUNDWAYS"
            + "THATAREOFTENDIFFICULTTOFULLYGRASPUNTILMUCHTIMEHASPASSEDANDPERSPECTIVEISGAINEDTHROUGH"
            + "REFLECTIONANDANALYSISOFTHERECORDSLEFBYPREVIOUSAGESANDCIVILIZATIONSTHATROSEANDFELL"
            + "ACCORDINGTOTHEIROWNCIRCUMSTANCESANDCHOICESMADEBYTHEIRLEADERSANDCITIZENSALIKETHROUGHOUT"
            + "THECOURSEOFHUMANHISTORYWHICHISFULLOFLESSONSANDINSIGHTSTHATCANHELPUSTOAVOIDREPEATING"
            + "MISTAKESOF THE PAST ANDTOBUILDMOREJUSTANDPROSPEROUSCOMMUNITIESFORTHEGENERATIONSTHAT"
            + "FOLLOWUSINTHEENDLESSJOURNEYOFPROGRESSANDDEVELOPMENTTHATCHARACTERIZESOURSPECIESAND"
            + "DRIVE US TOACHIEVE EVERGREATERHEIGHTSINALLAREASOFHUMANACTIVITYANDENDEAVORWITHOUT"
            + "LIMITORTIREDNESSASLONGASCURIOSITYANDTHE DESIRETOIMPROVEPERSISTIN THEHEARTSOFINDIVIDUALS"
            + "ANDSOCIETIESEVERYWHEREONTHISPLANETANDPERHAPSONEDAYBEYONDITASMANTKINDREACHESOUTINTO"
            + "SPACEANDSETSOUTTOEXPLOREOTHERWORLDSANDSTARSYSTEMSFARFROMHOMEINASEARCHFORNEWKNOWLEDGE"
            + "ANDPOSSIBILITIESTHATMAYTRANSFORMOURUNDERSTANDINGOFEXISTENCEANDOPENNEWHORIZONSFOR"
            + "THEFUTUREOFHUMANITYANDALLLIFE THATMAYACCOMPANYUSONTHISGREATADVENTUREINTOTHEUNKNOWN"
            + "REALMSOFTH EUNIVERSE WHEREWONDERSANDCHALLENGES AWAITTHOSEWHOAREBRAVEENOUGHTOVENTURE"
            + "FORTHANDDISCOVERWHATLIESBEYONDTHEBOUNDARIESOFOURCURRENTEXPERIENCEANDKNOWLEDGEIN"
            + "ANEVERENDINGQUESTFORTRUTHANDMEANINGTHATDEFINESWHATITMEANSTOBEHUMANANDALIVEINTHIS"
            + "REMARKABLEUNIVERSEOFENDLESSPOSSIBILITYANDMYSTERYTHATINVITESUS TOEXPLOREANDLEARN"
            + "WITHEVERYNEWDAYAND EVERYNEWDISCOVERY THATADVANCESOURCOLLECTIVEWISDOMANDCAPABILITY"
            + "ASASPECIESCAPABLEOFGREATTHINGSWHENWEWORKTOGETHERWITHPURPOSEANDUNITYTOWARDCOMMONGOALS"
            + "THATBENEFITALLANDPROTECTTHEFRAGILEBEAUTYOFTHEWORLDWEINHABITFORGENERATIONSTHATWILLCOME"
            + "AFTERUSANDINHERITTHERESULTSOFOURACTIONSTODAYANDINTHEYEARSAHEADASWESTRIVETOCREATEa"
            + "BETTERFUTUREFILLEDWITHHOPEOPPORTUNITYANDPEACEFOR EVERYONE WHO SHARESTHISJOURNEYTHROUGH"
            + "TIMEANDSPACEONTHEONLYHOMEWEHAVEKNOWNTHUSFARINTHEVASTNESS OFTHECOSMOS THATSURROUNDSUS"
            + "ANDREMINDSUSOFBOTH OURSMALLNESSAND OURPOTENTIAL FORGREATNESSIN THESCHEMEOFTHINGSTHAT"
            + "MAKEUPLIFEANDTHEUNIVERSEITSELFASWEKNOWITNOWANDASWEWILLDISCOVERITTOBEINTHETIMEYETTOCOME"
            + "WITHCONTINUED EFFORTANDDEDICATIONTOTHEPRINCIPLESOFSCIENCEREASONANDCOMPASSIONTHATGUIDE"
            + "USFORWARDINTOANEWERAOFUNDERSTANDINGANDCOOPERATIONAMONGALLPEOPLEANDNATIONSOFTHEEARTH"
            + "ANDPERHAPSEVENTUALLYWITHOTHERINTELLIGENTBEINGSWHOMAYEXISTELSEWHEREINTHEGALAXYORBEYOND"
            + "WAITING TOBEENCOUNTEREDBYUSINTHEFUTUREWHENWEHAVEDEVELOPEDTHEMEANSTO REACH THEMAND"
            + "COMMUNICATEACROSSTHEIMMENDISTANCESOFSPACEINAWAYTHATBRINGSKNOWLEDGEANDFRIENDSHIP"
            + "INSTEADOFCONFLICTORFEARASTHEHISTORYOFHUMANINTERACTIONSHASTAUGHTUSTOBECAREFULABOUT"
            + "WHENMEETINGTHEUNKNOWNANDTHEDIFFERENTFROM OURSELVESINTHISCOMPLEXWORLDWEINHABIT"
            + "TOGETHERWITHALLOTHERFORMSOFLIFE THATSHAREITWITHUSANDDEPENDONTHEHEALTHOFTHEPLANET"
            + "FOR THEIRCONTINUEDSURVIVALANDFLOURISHINGINTHEYEARSAHEADASMUCHASWEDOINTHISINTERDEPENDENT"
            + "WEB OFEXISTENCE THATCONNECTSEVERYTHINGAND EVERYONEINWAYSWEAREONLYBEGINNINGTOFULLY"
            + "APPRECIATEANDUNDERSTANDTHROUGHMODERN SCIENCEANDECOLOGICALAWARENESSTHATHELPUS TOSEE"
            + "THEBIGGERPICTUREAND TOACTRESPONSIBLYWITHREGARDTOTHENATURALWORLDANDITSRESOURCES"
            + "WHICHARELIMITEDANDMUSTBEUSEDWISELYIFWEARETOENSUREALIVABLEFUTUREFORALLWHOWILL"
            + "FOLLOWUSONTHISPLANETANDPERHAPSONOTHERWORLDSASWELLWHEN THE TIMECOMESFORHUMANITY"
            + "TOEXPANDBEYOND EARTHANDTOCARRYTHEFLAMEOFLIFEANDINTELLIGENCEOUTINTOTHESTARS"
            + "INANACTOFCOSMICSIGNIFICANCETHATWILL MARKA NEWCHAPTERINTHESTORYOF EXISTENCEITSELF"
            + "ASWEKNOWITANDASITMAYCOME TOBEKNOWNIN THEAGESYETTOARRIVEWITH THEPASSAGE OFTIME"
            + "ANDTHEUNFOLDINGOFEVENTS THATSHAPE THEDESTINYOF SPECIESANDCIVILIZATIONS THROUGHOUT"
            + "THEGALAXYAND THEUNIVERS E AT LARGE IN WAYS THAT ARE BOTH BEAUTIFUL AND MYSTERIOUS"
            + "TO CONTEMPLATE AND TO EXPLORE WITH THE TOOLS OF SCIENCE AND THE SPIRIT OF ADVENTURE"
            + "THAT HAVE ALWAYS DRIVEN HUMAN PROGRESS AND DISCOVERY FROM THE EARLIEST DAYS OF OUR"
            + "HISTORY UP TO THE PRESENT MOMENT AND ON INTO THE FUTURE THAT AWAITS US WITH ALL ITS"
            + "PROMISE AND POSSIBILITY FOR GROWTH AND UNDERSTANDING BEYOND ANYTHING WE CAN CURRENTLY"
            + "IMAGINE OR PREDICT WITH CERTAINTY IN THIS EVER CHANGING AND EXPANDING REALITY WE CALL"
            + "HOME AND THE UNIVERSE THAT CONTAINS IT ALL IN ITS IMMENSITY AND COMPLEXITY THAT CHALLENGES"
            + "AND INSPIRES US DAILY TO SEEK MORE KNOWLEDGE AND TO STRIVE FOR BETTER WAYS OF LIVING"
            + "TOGETHER IN PEACE AND HARMONY WITH EACH OTHER AND WITH THE NATURAL WORLD THAT SUSTAINS"
            + "US AND ALL OTHER LIFE FORMS ON THIS PRECIOUS PLANET EARTH THAT WE MUST CARE FOR AND"
            + "PROTECT AS OUR MOST IMPORTANT RESPONSIBILITY TO FUTURE GENERATIONS AND TO THE CONTINUITY"
            + "OF LIFE ITSELF IN THE COSMOS WHERE WE ARE BUT ONE SMALL PART OF A MUCH LARGER AND"
            + "WONDROUS WHOLE THAT DESERVES OUR RESPECT AND OUR BEST EFFORTS TO UNDERSTAND AND PRESERVE"
            + "FOR AS LONG AS POSSIBLE IN THE FACE OF ALL CHALLENGES AND CHANGES THAT TIME BRINGS"
            + "TO EVERYTHING THAT EXISTS IN THIS REMARKABLE AND ENIGMATIC UNIVERSE OF OURS.";

        static EnigmaPredictGrokService()
        {
            if (TrainingText.Length < 5000)
                throw new InvalidOperationException("TrainingText must contain at least 5000 letters.");

            // Build forward / inverse maps
            for (int r = 0; r < 5; r++)
            {
                Fwd[r] = new int[26];
                Inv[r] = new int[26];
                for (int i = 0; i < 26; i++)
                {
                    int outC = RotorWirings[r][i] - 'A';
                    Fwd[r][i] = outC;
                    Inv[r][outC] = i;
                }
                Notch[r] = NotchLetters[r] - 'A';
            }

            // Reflector
            for (int i = 0; i < 26; i++)
                Refl[i] = ReflectorB[i] - 'A';

            // Build n-gram tables with add-one smoothing
            int[] biCount = new int[26 * 26];
            int[] triCount = new int[26 * 26 * 26];
            int biTotal = 0, triTotal = 0;

            for (int i = 0; i < TrainingText.Length; i++)
            {
                char c = TrainingText[i];
                if (c < 'A' || c > 'Z') continue;
                int cur = c - 'A';

                if (i + 1 < TrainingText.Length)
                {
                    char n = TrainingText[i + 1];
                    if (n >= 'A' && n <= 'Z')
                    {
                        int next = n - 'A';
                        biCount[cur * 26 + next]++;
                        biTotal++;
                    }
                }
                if (i + 2 < TrainingText.Length)
                {
                    char n1 = TrainingText[i + 1];
                    char n2 = TrainingText[i + 2];
                    if (n1 >= 'A' && n1 <= 'Z' && n2 >= 'A' && n2 <= 'Z')
                    {
                        int next1 = n1 - 'A';
                        int next2 = n2 - 'A';
                        triCount[cur * 676 + next1 * 26 + next2]++;
                        triTotal++;
                    }
                }
            }

            for (int i = 0; i < 26 * 26; i++)
                BigramLog[i] = (float)Math.Log((biCount[i] + 1.0) / (biTotal + 26.0 * 26.0));
            for (int i = 0; i < 26 * 26 * 26; i++)
                TrigramLog[i] = (float)Math.Log((triCount[i] + 1.0) / (triTotal + 26.0 * 26.0 * 26.0));
        }

        // ------------------------------------------------------------------
        // Public API
        // ------------------------------------------------------------------
        public async Task<EnigmaSettings> CrackAsync(string ciphertext, CancellationToken cancellationToken = default)
        {
            var d = await CrackDetailedAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            return new EnigmaSettings(
                d.StartPositions[0],
                d.StartPositions[1],
                d.StartPositions[2],
                d.PlugboardPairs.ToList());
        }

        public Task<CrackDetails> CrackDetailedAsync(string ciphertext, CancellationToken cancellationToken = default)
        {
            return Task.Run(() => CrackCore(ciphertext, cancellationToken), cancellationToken);
        }

        // ------------------------------------------------------------------
        // Core attack
        // ------------------------------------------------------------------
        private CrackDetails CrackCore(string ciphertext, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("Ciphertext must not be empty.");

            // Normalise to 0-25
            var src = new int[ciphertext.Length];
            int n = 0;
            foreach (char c in ciphertext)
            {
                if (c >= 'A' && c <= 'Z') src[n++] = c - 'A';
                else if (c >= 'a' && c <= 'z') src[n++] = c - 'a';
            }
            if (n == 0) throw new ArgumentException("No letters in ciphertext.");
            Array.Resize(ref src, n);

            // All 60 rotor orders
            var orders = new List<(int L, int M, int R)>(60);
            for (int a = 0; a < 5; a++)
                for (int b = 0; b < 5; b++)
                    if (b != a)
                        for (int c = 0; c < 5; c++)
                            if (c != a && c != b)
                                orders.Add((a, b, c));

            // ========== STAGE 1 ==========
            var stage1Candidates = new List<Candidate>(K1);
            var lockObj = new object();
            var po = new ParallelOptions
            {
                CancellationToken = ct,
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            Parallel.ForEach(orders, po,
                () => new List<Candidate>(256),
                (order, state, localList) =>
                {
                    ct.ThrowIfCancellationRequested();
                    int len = Math.Min(n, Stage1Len);
                    var buf = new int[len];
                    var pb = IdentityPlug();

                    for (int sl = 0; sl < 26; sl++)
                        for (int sm = 0; sm < 26; sm++)
                            for (int sr = 0; sr < 26; sr++)
                            {
                                DecryptInto(src, 0, len, buf, order.L, order.M, order.R, sl, sm, sr, pb);
                                double score = IoC(buf, len);
                                localList.Add(new Candidate
                                {
                                    L = order.L,
                                    M = order.M,
                                    R = order.R,
                                    SL = sl,
                                    SM = sm,
                                    SR = sr,
                                    Score = score,
                                    Plug = null
                                });
                            }
                    // keep only local top
                    if (localList.Count > 400)
                    {
                        localList.Sort((x, y) => y.Score.CompareTo(x.Score));
                        localList.RemoveRange(400, localList.Count - 400);
                    }
                    return localList;
                },
                localList =>
                {
                    lock (lockObj)
                    {
                        stage1Candidates.AddRange(localList);
                    }
                });

            stage1Candidates.Sort((a, b) => b.Score.CompareTo(a.Score));
            if (stage1Candidates.Count > K1)
                stage1Candidates.RemoveRange(K1, stage1Candidates.Count - K1);

            // ========== STAGE 2 ==========
            var stage2Candidates = new List<Candidate>(K2);
            Parallel.ForEach(stage1Candidates, po,
                () => new List<Candidate>(32),
                (cand, state, localList) =>
                {
                    ct.ThrowIfCancellationRequested();
                    int len = Math.Min(n, Stage2Len);
                    var buf = new int[len];
                    var pb = IdentityPlug();
                    // cheap steepest ascent up to MaxStage2Pairs
                    SteepestAscentIoc(src, len, buf, cand.L, cand.M, cand.R, cand.SL, cand.SM, cand.SR, pb, MaxStage2Pairs);
                    DecryptInto(src, 0, len, buf, cand.L, cand.M, cand.R, cand.SL, cand.SM, cand.SR, pb);
                    double score = IoC(buf, len);
                    localList.Add(new Candidate
                    {
                        L = cand.L,
                        M = cand.M,
                        R = cand.R,
                        SL = cand.SL,
                        SM = cand.SM,
                        SR = cand.SR,
                        Score = score,
                        Plug = (int[])pb.Clone()
                    });
                    return localList;
                },
                localList =>
                {
                    lock (lockObj)
                    {
                        stage2Candidates.AddRange(localList);
                    }
                });

            stage2Candidates.Sort((a, b) => b.Score.CompareTo(a.Score));
            if (stage2Candidates.Count > K2)
                stage2Candidates.RemoveRange(K2, stage2Candidates.Count - K2);

            // ========== STAGE 3 ==========
            var stage3Results = new List<Candidate>(K2);
            Parallel.ForEach(stage2Candidates, po,
                () => new List<Candidate>(4),
                (cand, state, localList) =>
                {
                    ct.ThrowIfCancellationRequested();
                    var pb = cand.Plug != null ? (int[])cand.Plug.Clone() : IdentityPlug();
                    var buf = new int[n];
                    SteepestAscentNgram(src, n, buf, cand.L, cand.M, cand.R, cand.SL, cand.SM, cand.SR, pb, MaxPairs);
                    DecryptInto(src, 0, n, buf, cand.L, cand.M, cand.R, cand.SL, cand.SM, cand.SR, pb);
                    double score = NgramScore(buf, n);
                    localList.Add(new Candidate
                    {
                        L = cand.L,
                        M = cand.M,
                        R = cand.R,
                        SL = cand.SL,
                        SM = cand.SM,
                        SR = cand.SR,
                        Score = score,
                        Plug = pb
                    });
                    return localList;
                },
                localList =>
                {
                    lock (lockObj)
                    {
                        stage3Results.AddRange(localList);
                    }
                });

            stage3Results.Sort((a, b) => b.Score.CompareTo(a.Score));
            if (stage3Results.Count > M)
                stage3Results.RemoveRange(M, stage3Results.Count - M);

            // ========== STAGE 4 – compound polish ==========
            Candidate best = null!;
            double bestScore = double.NegativeInfinity;
            object bestLock = new object();

            Parallel.ForEach(stage3Results, po, cand =>
            {
                ct.ThrowIfCancellationRequested();
                var pb = (int[])cand.Plug!.Clone();
                var buf = new int[n];
                CompoundPolish(src, n, buf, cand.L, cand.M, cand.R, cand.SL, cand.SM, cand.SR, pb);
                DecryptInto(src, 0, n, buf, cand.L, cand.M, cand.R, cand.SL, cand.SM, cand.SR, pb);
                double score = NgramScore(buf, n);
                lock (bestLock)
                {
                    if (score > bestScore)
                    {
                        bestScore = score;
                        best = new Candidate
                        {
                            L = cand.L,
                            M = cand.M,
                            R = cand.R,
                            SL = cand.SL,
                            SM = cand.SM,
                            SR = cand.SR,
                            Score = score,
                            Plug = pb
                        };
                    }
                }
            });

            // Build final result
            var finalPb = best.Plug!;
            var finalBuf = new int[n];
            DecryptInto(src, 0, n, finalBuf, best.L, best.M, best.R, best.SL, best.SM, best.SR, finalPb);

            var pairs = new List<string>();
            var seen = new bool[26];
            for (int i = 0; i < 26; i++)
            {
                if (!seen[i] && finalPb[i] != i)
                {
                    int j = finalPb[i];
                    if (i < j)
                    {
                        pairs.Add(((char)('A' + i)).ToString() + (char)('A' + j));
                        seen[i] = seen[j] = true;
                    }
                }
            }

            var plaintext = new string(finalBuf.Select(x => (char)('A' + x)).ToArray());

            return new CrackDetails(
                new[] { RotorNames[best.L], RotorNames[best.M], RotorNames[best.R] },
                new[] { (char)('A' + best.SL), (char)('A' + best.SM), (char)('A' + best.SR) },
                pairs,
                plaintext,
                best.Score);
        }

        // ------------------------------------------------------------------
        // Cipher primitives (allocation-free DecryptInto)
        // ------------------------------------------------------------------
        private static int[] IdentityPlug()
        {
            var p = new int[26];
            for (int i = 0; i < 26; i++) p[i] = i;
            return p;
        }

        private static void DecryptInto(
            int[] src, int offset, int len, int[] dst,
            int leftR, int midR, int rightR,
            int startL, int startM, int startR,
            int[] plug)
        {
            int posL = startL, posM = startM, posR = startR;
            int notchM = Notch[midR], notchR = Notch[rightR];

            for (int i = 0; i < len; i++)
            {
                // step
                if (posM == notchM)
                {
                    posL = (posL + 1) % 26;
                    posM = (posM + 1) % 26;
                }
                else if (posR == notchR)
                {
                    posM = (posM + 1) % 26;
                }
                posR = (posR + 1) % 26;

                int x = plug[src[offset + i]];

                // right rotor forward
                x = (Fwd[rightR][(x + posR) % 26] - posR + 26) % 26;
                // middle
                x = (Fwd[midR][(x + posM) % 26] - posM + 26) % 26;
                // left
                x = (Fwd[leftR][(x + posL) % 26] - posL + 26) % 26;
                // reflector
                x = Refl[x];
                // left inverse
                x = (Inv[leftR][(x + posL) % 26] - posL + 26) % 26;
                // middle inverse
                x = (Inv[midR][(x + posM) % 26] - posM + 26) % 26;
                // right inverse
                x = (Inv[rightR][(x + posR) % 26] - posR + 26) % 26;

                dst[i] = plug[x];
            }
        }

        // Public static Encrypt for known-answer tests
        public static string Encrypt(
            string plaintext,
            int leftR, int midR, int rightR,
            int startL, int startM, int startR,
            int[]? plug = null)
        {
            plug ??= IdentityPlug();
            var src = plaintext.Select(c => c - 'A').ToArray();
            var dst = new int[src.Length];
            DecryptInto(src, 0, src.Length, dst, leftR, midR, rightR, startL, startM, startR, plug);
            return new string(dst.Select(x => (char)('A' + x)).ToArray());
        }

        // ------------------------------------------------------------------
        // Scoring
        // ------------------------------------------------------------------
        private static double IoC(int[] buf, int len)
        {
            Span<int> cnt = stackalloc int[26];
            for (int i = 0; i < len; i++) cnt[buf[i]]++;
            double sum = 0;
            for (int i = 0; i < 26; i++)
                sum += cnt[i] * (cnt[i] - 1.0);
            return len > 1 ? sum / (len * (len - 1.0)) : 0.0;
        }

        private static double NgramScore(int[] buf, int len)
        {
            if (len < 3) return 0.0;
            double s = 0;
            for (int i = 0; i < len - 1; i++)
                s += BigramLog[buf[i] * 26 + buf[i + 1]];
            for (int i = 0; i < len - 2; i++)
                s += TrigramLog[buf[i] * 676 + buf[i + 1] * 26 + buf[i + 2]];
            return s;
        }

        // ------------------------------------------------------------------
        // Steepest-ascent single-move plugboard search
        // ------------------------------------------------------------------
        private static void SteepestAscentIoc(
            int[] src, int len, int[] buf,
            int l, int m, int r, int sl, int sm, int sr,
            int[] pb, int maxPairs)
        {
            var scratch = new int[26];
            while (true)
            {
                double bestGain = 0;
                int bestX = -1, bestY = -1;
                bool isUnplug = false;

                DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, pb);
                double baseScore = IoC(buf, len);
                int currentPairs = CountPairs(pb);

                // evaluate all connect moves
                for (int x = 0; x < 26; x++)
                {
                    for (int y = x + 1; y < 26; y++)
                    {
                        if (pb[x] == y) continue; // already paired
                        Array.Copy(pb, scratch, 26);
                        // unplug existing partners if any
                        if (scratch[x] != x) { int p = scratch[x]; scratch[x] = x; scratch[p] = p; }
                        if (scratch[y] != y) { int p = scratch[y]; scratch[y] = y; scratch[p] = p; }
                        // connect
                        scratch[x] = y; scratch[y] = x;
                        if (CountPairs(scratch) > maxPairs) continue;

                        DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, scratch);
                        double sc = IoC(buf, len);
                        double gain = sc - baseScore;
                        if (gain > bestGain)
                        {
                            bestGain = gain;
                            bestX = x; bestY = y;
                            isUnplug = false;
                        }
                    }
                }

                // evaluate unplug moves
                for (int x = 0; x < 26; x++)
                {
                    if (pb[x] <= x) continue;
                    int y = pb[x];
                    Array.Copy(pb, scratch, 26);
                    scratch[x] = x; scratch[y] = y;
                    DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, scratch);
                    double sc = IoC(buf, len);
                    double gain = sc - baseScore;
                    if (gain > bestGain)
                    {
                        bestGain = gain;
                        bestX = x; bestY = y;
                        isUnplug = true;
                    }
                }

                if (bestGain < MinGainIoc) break;

                if (isUnplug)
                {
                    int y = pb[bestX];
                    pb[bestX] = bestX; pb[y] = y;
                }
                else
                {
                    if (pb[bestX] != bestX) { int p = pb[bestX]; pb[bestX] = bestX; pb[p] = p; }
                    if (pb[bestY] != bestY) { int p = pb[bestY]; pb[bestY] = bestY; pb[p] = p; }
                    pb[bestX] = bestY; pb[bestY] = bestX;
                }
            }
        }

        private static void SteepestAscentNgram(
            int[] src, int len, int[] buf,
            int l, int m, int r, int sl, int sm, int sr,
            int[] pb, int maxPairs)
        {
            var scratch = new int[26];
            while (true)
            {
                double bestGain = 0;
                int bestX = -1, bestY = -1;
                bool isUnplug = false;

                DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, pb);
                double baseScore = NgramScore(buf, len);

                for (int x = 0; x < 26; x++)
                {
                    for (int y = x + 1; y < 26; y++)
                    {
                        if (pb[x] == y) continue;
                        Array.Copy(pb, scratch, 26);
                        if (scratch[x] != x) { int p = scratch[x]; scratch[x] = x; scratch[p] = p; }
                        if (scratch[y] != y) { int p = scratch[y]; scratch[y] = y; scratch[p] = p; }
                        scratch[x] = y; scratch[y] = x;
                        if (CountPairs(scratch) > maxPairs) continue;

                        DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, scratch);
                        double sc = NgramScore(buf, len);
                        double gain = sc - baseScore;
                        if (gain > bestGain)
                        {
                            bestGain = gain;
                            bestX = x; bestY = y;
                            isUnplug = false;
                        }
                    }
                }

                for (int x = 0; x < 26; x++)
                {
                    if (pb[x] <= x) continue;
                    int y = pb[x];
                    Array.Copy(pb, scratch, 26);
                    scratch[x] = x; scratch[y] = y;
                    DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, scratch);
                    double sc = NgramScore(buf, len);
                    double gain = sc - baseScore;
                    if (gain > bestGain)
                    {
                        bestGain = gain;
                        bestX = x; bestY = y;
                        isUnplug = true;
                    }
                }

                if (bestGain < MinGainNgram) break;

                if (isUnplug)
                {
                    int y = pb[bestX];
                    pb[bestX] = bestX; pb[y] = y;
                }
                else
                {
                    if (pb[bestX] != bestX) { int p = pb[bestX]; pb[bestX] = bestX; pb[p] = p; }
                    if (pb[bestY] != bestY) { int p = pb[bestY]; pb[bestY] = bestY; pb[p] = p; }
                    pb[bestX] = bestY; pb[bestY] = bestX;
                }
            }
        }

        // ------------------------------------------------------------------
        // Compound-move polish (Stage 4)
        // ------------------------------------------------------------------
        private static void CompoundPolish(
            int[] src, int len, int[] buf,
            int l, int m, int r, int sl, int sm, int sr,
            int[] pb)
        {
            var scratch1 = new int[26];
            var scratch2 = new int[26];

            while (true)
            {
                DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, pb);
                double baseScore = NgramScore(buf, len);
                double bestGain = 0;
                int bestAx = -1, bestAy = -1, bestBx = -1, bestBy = -1;
                bool bestAUnplug = false, bestBUnplug = false;

                // Build list of candidate single moves
                var moves = new List<(int x, int y, bool unplug)>(200);
                for (int x = 0; x < 26; x++)
                    for (int y = x + 1; y < 26; y++)
                        if (pb[x] != y)
                            moves.Add((x, y, false));
                for (int x = 0; x < 26; x++)
                    if (pb[x] > x)
                        moves.Add((x, pb[x], true));

                for (int i = 0; i < moves.Count; i++)
                {
                    var (ax, ay, aUnplug) = moves[i];
                    Array.Copy(pb, scratch1, 26);
                    ApplyMove(scratch1, ax, ay, aUnplug);
                    if (CountPairs(scratch1) > MaxPairs) continue;

                    for (int j = 0; j < moves.Count; j++)
                    {
                        if (i == j) continue;
                        var (bx, by, bUnplug) = moves[j];
                        Array.Copy(scratch1, scratch2, 26);
                        // recompute the second move on the board after the first
                        // (simple approach: try the same letter pair / unplug)
                        if (bUnplug)
                        {
                            if (scratch2[bx] != by && scratch2[by] != bx) continue;
                            ApplyMove(scratch2, bx, by, true);
                        }
                        else
                        {
                            ApplyMove(scratch2, bx, by, false);
                        }
                        if (CountPairs(scratch2) > MaxPairs) continue;

                        DecryptInto(src, 0, len, buf, l, m, r, sl, sm, sr, scratch2);
                        double sc = NgramScore(buf, len);
                        double gain = sc - baseScore;
                        if (gain > bestGain)
                        {
                            bestGain = gain;
                            bestAx = ax; bestAy = ay; bestAUnplug = aUnplug;
                            bestBx = bx; bestBy = by; bestBUnplug = bUnplug;
                        }
                    }
                }

                if (bestGain < MinGainNgram) break;

                ApplyMove(pb, bestAx, bestAy, bestAUnplug);
                ApplyMove(pb, bestBx, bestBy, bestBUnplug);
            }
        }

        private static void ApplyMove(int[] pb, int x, int y, bool unplug)
        {
            if (unplug)
            {
                if (pb[x] == y)
                {
                    pb[x] = x; pb[y] = y;
                }
            }
            else
            {
                if (pb[x] != x) { int p = pb[x]; pb[x] = x; pb[p] = p; }
                if (pb[y] != y) { int p = pb[y]; pb[y] = y; pb[p] = p; }
                pb[x] = y; pb[y] = x;
            }
        }

        private static int CountPairs(int[] pb)
        {
            int c = 0;
            for (int i = 0; i < 26; i++)
                if (pb[i] > i) c++;
            return c;
        }

        // ------------------------------------------------------------------
        // Internal candidate structure
        // ------------------------------------------------------------------
        private sealed class Candidate
        {
            public int L, M, R;
            public int SL, SM, SR;
            public double Score;
            public int[]? Plug;
        }
    }
}