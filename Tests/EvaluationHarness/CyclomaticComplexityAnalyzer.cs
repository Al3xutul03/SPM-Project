using System.Text;
using System.Text.RegularExpressions;

namespace Tests.EvaluationHarness;

/// <summary>
/// Per-method McCabe Cyclomatic Complexity measurement.
/// </summary>
public sealed record MethodComplexityMetric(
    string FileName,
    string MethodSignature,
    int CyclomaticComplexity,
    bool ExceedsMcCabeThreshold
);

/// <summary>
/// Summary of Cyclomatic Complexity (McCabe, 1976) for a source file or service class.
/// McCabe describes 10 as a reasonable upper bound per function.
/// </summary>
public sealed record FileComplexityReport(
    string FilePath,
    int MethodCount,
    double AverageCyclomaticComplexity,
    int MaxCyclomaticComplexity,
    int MethodsExceedingThreshold,
    IReadOnlyList<MethodComplexityMetric> Methods
);

/// <summary>
/// Automated static analyzer computing McCabe's Cyclomatic Complexity (McCabe, 1976)
/// across C# source files in <c>EnigmaLogic/Services</c>.
///
/// Formula: M = 1 + d, where d is the number of predicate decision points in a function:
/// <c>if</c>, <c>for</c>, <c>foreach</c>, <c>while</c>, <c>case</c>, <c>catch</c>,
/// conditional ternary <c>?:</c>, null-coalescing <c>??</c>, boolean short-circuit <c>&amp;&amp;</c>, <c>||</c>,
/// pattern combinators <c>and</c>, <c>or</c>, and switch expression arms <c>=&gt;</c>.
/// </summary>
public static class CyclomaticComplexityAnalyzer
{
    public const int McCabeRecommendedUpperBound = 10;

    private static readonly Regex MethodHeaderPattern = new(
        @"(?<![\w.])(?:public|private|protected|internal)\s+(?:(?:static|async|virtual|override|sealed|readonly|unsafe|new|partial)\s+)*[\w<>\[\],\.\?\(\)\s]+\s+(?<name>[A-Za-z_]\w*)\s*(?:<[^>]+>)?\s*\([^;{}]*\)\s*(?:where\s+[^{;]+)?\{",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex DecisionPointsPattern = new(
        @"\b(?:if|for|foreach|while|case|catch|and|or)\b|&&|\|\||\?\?(?!=)|\?(?![\.\?\w\[])",
        RegexOptions.Compiled);

    /// <summary>
    /// Analyzes a C# file on disk and returns McCabe cyclomatic complexity metrics per method.
    /// </summary>
    public static FileComplexityReport AnalyzeFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        string sourceCode = File.ReadAllText(filePath);
        return AnalyzeSource(sourceCode, Path.GetFileName(filePath));
    }

    /// <summary>
    /// Analyzes raw C# source code and computes McCabe cyclomatic complexity per method.
    /// </summary>
    public static FileComplexityReport AnalyzeSource(string sourceCode, string fileName = "InMemory.cs")
    {
        ArgumentNullException.ThrowIfNull(sourceCode);

        string sanitized = StripCommentsAndLiterals(sourceCode);
        var methods = new List<MethodComplexityMetric>();

        foreach (Match match in MethodHeaderPattern.Matches(sanitized))
        {
            string methodName = match.Groups["name"].Value;

            // Skip C# control keywords if accidentally matched
            if (methodName is "if" or "for" or "foreach" or "while" or "switch" or "catch" or "lock" or "using")
            {
                continue;
            }

            int openBraceIndex = match.Index + match.Length - 1;
            string? body = ExtractBalancedBraceBlock(sanitized, openBraceIndex);
            if (body is null)
            {
                continue;
            }

            int complexity = ComputeBodyComplexity(body);
            methods.Add(new MethodComplexityMetric(
                FileName: fileName,
                MethodSignature: methodName,
                CyclomaticComplexity: complexity,
                ExceedsMcCabeThreshold: complexity > McCabeRecommendedUpperBound
            ));
        }

        if (methods.Count == 0)
        {
            return new FileComplexityReport(fileName, 0, 0.0, 0, 0, []);
        }

        double avg = methods.Average(m => m.CyclomaticComplexity);
        int max = methods.Max(m => m.CyclomaticComplexity);
        int exceeding = methods.Count(m => m.ExceedsMcCabeThreshold);

        return new FileComplexityReport(
            FilePath: fileName,
            MethodCount: methods.Count,
            AverageCyclomaticComplexity: avg,
            MaxCyclomaticComplexity: max,
            MethodsExceedingThreshold: exceeding,
            Methods: methods
        );
    }

    /// <summary>
    /// Computes McCabe cyclomatic complexity M = 1 + decision_points for a method body.
    /// </summary>
    public static int ComputeBodyComplexity(string methodBody)
    {
        string sanitized = StripCommentsAndLiterals(methodBody);
        int decisionCount = DecisionPointsPattern.Matches(sanitized).Count;
        return 1 + decisionCount;
    }

    private static string? ExtractBalancedBraceBlock(string text, int openBraceIndex)
    {
        if (openBraceIndex < 0 || openBraceIndex >= text.Length || text[openBraceIndex] != '{')
        {
            return null;
        }

        int depth = 0;
        for (int i = openBraceIndex; i < text.Length; i++)
        {
            if (text[i] == '{')
            {
                depth++;
            }
            else if (text[i] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return text.Substring(openBraceIndex + 1, i - openBraceIndex - 1);
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Replaces single-line comments, multi-line comments, string literals, and character literals
    /// with spaces while preserving brace structure and line/token boundaries.
    /// </summary>
    private static string StripCommentsAndLiterals(string code)
    {
        var sb = new StringBuilder(code.Length);
        int i = 0;

        while (i < code.Length)
        {
            // Single-line comment //
            if (i + 1 < code.Length && code[i] == '/' && code[i + 1] == '/')
            {
                i += 2;
                while (i < code.Length && code[i] != '\n')
                {
                    i++;
                }
                continue;
            }

            // Multi-line comment /* ... */
            if (i + 1 < code.Length && code[i] == '/' && code[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < code.Length && !(code[i] == '*' && code[i + 1] == '/'))
                {
                    if (code[i] == '\n') sb.Append('\n');
                    i++;
                }
                i += 2;
                continue;
            }

            // String literal "..."
            if (code[i] == '"')
            {
                sb.Append("\"\"");
                i++;
                while (i < code.Length && code[i] != '"')
                {
                    if (code[i] == '\\' && i + 1 < code.Length)
                    {
                        i += 2;
                        continue;
                    }
                    i++;
                }
                i++;
                continue;
            }

            // Char literal '.'
            if (code[i] == '\'')
            {
                sb.Append("''");
                i++;
                while (i < code.Length && code[i] != '\'')
                {
                    if (code[i] == '\\' && i + 1 < code.Length)
                    {
                        i += 2;
                        continue;
                    }
                    i++;
                }
                i++;
                continue;
            }

            sb.Append(code[i]);
            i++;
        }

        return sb.ToString();
    }
}
