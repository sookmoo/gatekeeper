using System.Text.RegularExpressions;

namespace Gatekeeper.Domain;

public static partial class Validation
{
    public const int MaxNameLength = 64;
    public const int MaxTextLength = 256;

    // Lowercase slug: letters, digits, '.', '_', '-'; must start with a letter or digit.
    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]*$")]
    private static partial Regex Slug();

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    private static partial Regex EmailShape();

    public static void AppName(string? name) => Throw(Check(("name", SlugError(name))));

    public static void RoleFields(string? name, string? description) =>
        Throw(Check(
            ("name", SlugError(name)),
            ("description", Length(description, MaxTextLength, required: false))));

    public static void UserFields(string? username, string? email, string? displayName) =>
        Throw(Check(
            ("username", SlugError(username)),
            ("email", EmailError(email)),
            ("displayName", Length(displayName, MaxTextLength, required: false))));

    private static string? SlugError(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "is required.";
        if (value.Length > MaxNameLength) return $"must be at most {MaxNameLength} characters.";
        return Slug().IsMatch(value)
            ? null
            : "must be lowercase letters, digits, '.', '_' or '-', starting with a letter or digit.";
    }

    private static string? EmailError(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "is required.";
        if (value.Length > MaxTextLength) return $"must be at most {MaxTextLength} characters.";
        return EmailShape().IsMatch(value) ? null : "must be a valid email address.";
    }

    private static string? Length(string? value, int max, bool required)
    {
        if (string.IsNullOrWhiteSpace(value)) return required ? "is required." : null;
        return value.Length > max ? $"must be at most {max} characters." : null;
    }

    private static Dictionary<string, string> Check(params (string Field, string? Error)[] checks) =>
        checks.Where(c => c.Error is not null).ToDictionary(c => c.Field, c => c.Error!);

    private static void Throw(Dictionary<string, string> errors)
    {
        if (errors.Count > 0) throw new ValidationException(errors);
    }
}
