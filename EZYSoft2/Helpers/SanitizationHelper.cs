using System.Text.RegularExpressions;
using System.Web;

public static class SanitizationHelper
{
    public static string SanitizeInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return input;

        // 🔹 Remove potential SQL Injection and XSS threats
        input = HttpUtility.HtmlEncode(input); // Prevent XSS
        return input;
    }
}
