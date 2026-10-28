using System.Buffers;
using System.Text;
using System.Text.RegularExpressions;

namespace Gatekeeper.Domain;

public static partial class Validation
{
    public const int MaxNameLength = 64;
    public const int MaxTextLength = 256;

    // Lowercase slug: letters, digits, '.', '_', '-'; must start with a letter or digit.
    [GeneratedRegex(@"\A[a-z0-9][a-z0-9._-]*\z")]
    private static partial Regex Slug();

    // ASCII only: printable local part, dotted ASCII domain. Keeps case folding identical in every store.
    [GeneratedRegex(@"\A[!-?A-~]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\z")]
    private static partial Regex EmailShape();

    /// <summary>True if the text has the shape of a username (lowercase slug, at most 64 characters). Case-folded input is accepted.</summary>
    public static bool LooksLikeUsername(string? value) =>
        value is { Length: > 0 and <= MaxNameLength } && Slug().IsMatch(value.ToLowerInvariant());

    public static void AppName(string? name) => Throw(Check(("name", SlugError(name))));

    public static void ClientName(string? name) => Throw(Check(("name", SlugError(name))));

    public static void RoleFields(string? name, string? description) =>
        Throw(Check(
            ("name", SlugError(name)),
            ("description", Length(description, MaxTextLength, required: false))));

    public static void UserFields(string? username, string? email, string? displayName) =>
        Throw(Check(
            ("username", SlugError(username)),
            ("email", EmailError(email)),
            ("displayName", Length(displayName, MaxTextLength, required: false))));

    public const int MinPrefixLength = 2;

    /// <summary>Filters of the user list: a prefix is at least <see cref="MinPrefixLength"/> characters (a one-letter search would list nearly everyone) and clean text.</summary>
    public static void UserListFilters(string? usernamePrefix, string? emailPrefix) =>
        Throw(Check(("usernamePrefix", PrefixError(usernamePrefix)), ("emailPrefix", PrefixError(emailPrefix))));

    private static string? PrefixError(string? value)
    {
        if (value is null) return null;
        if (value.Length < MinPrefixLength) return $"must be at least {MinPrefixLength} characters.";
        return Length(value, MaxTextLength, required: false);
    }

    public static readonly TimeSpan DefaultTestLifetime = TimeSpan.FromDays(30);
    public static readonly TimeSpan MaxTestLifetime = TimeSpan.FromDays(365);

    /// <summary>
    /// Only test accounts have an expiry; it must lie in the future and at most <see cref="MaxTestLifetime"/> ahead.
    /// An unchanged expiry (<paramref name="current"/>) is accepted as is, so renaming a user near its expiry still works.
    /// </summary>
    public static void UserLifetime(UserKind kind, DateTimeOffset? expiresAt, DateTimeOffset now, DateTimeOffset? current = null) =>
        Throw(Check(
            ("kind", Enum.IsDefined(kind) ? null : "is not a valid user kind."),
            ("expiresAt", Enum.IsDefined(kind) ? LifetimeError(kind, expiresAt, now, current) : null)));

    private static string? LifetimeError(UserKind kind, DateTimeOffset? expiresAt, DateTimeOffset now, DateTimeOffset? current)
    {
        if (kind != UserKind.Test) return expiresAt is null ? null : "is only allowed for test users.";
        if (expiresAt is null) return "is required for test users.";
        if (expiresAt == current) return null;
        if (expiresAt <= now) return "must be in the future.";
        if (expiresAt > now + MaxTestLifetime) return $"must be at most {MaxTestLifetime.Days} days ahead.";
        return null;
    }

    public const int MinPasswordLength = 12;
    public const int MaxPasswordLength = 128;

    /// <summary>Length rules only (no composition rules). Control characters and malformed Unicode are refused.</summary>
    public static void Password(string? password, string field = "password") => Throw(Check((field, PasswordError(password))));

    private static string? PasswordError(string? value)
    {
        if (value is null) return "is required.";
        if (value.Length < MinPasswordLength) return $"must be at least {MinPasswordLength} characters.";
        if (value.Length > MaxPasswordLength) return $"must be at most {MaxPasswordLength} characters.";
        return IsCleanText(value) ? null : "must not contain control characters or invalid Unicode.";
    }

    private static string? SlugError(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "is required.";
        if (value.Length > MaxNameLength) return $"must be at most {MaxNameLength} characters.";
        if (!Slug().IsMatch(value))
            return "must be lowercase letters, digits, '.', '_' or '-', starting with a letter or digit.";
        // The CLI accepts a name or an id; a name that parses as a GUID would be ambiguous.
        return Guid.TryParse(value, out _) ? "must not look like a GUID." : null;
    }

    private static string? EmailError(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "is required.";
        if (value.Length > MaxTextLength) return $"must be at most {MaxTextLength} characters.";
        return EmailShape().IsMatch(value) ? null : "must be a valid email address.";
    }

    private static string? Length(string? value, int max, bool required)
    {
        if (value is null) return required ? "is required." : null;
        if (required && string.IsNullOrWhiteSpace(value)) return "is required.";
        if (value.Length > max) return $"must be at most {max} characters.";
        return IsCleanText(value) ? null : "must not contain control characters or invalid Unicode.";
    }

    /// <summary>
    /// True if the text is well-formed UTF-16 with no control characters (NUL, ESC, CR/LF, ...) and
    /// no bidirectional override/isolate characters. Postgres cannot store NUL, and the rest can be
    /// used to spoof terminal or log output.
    /// </summary>
    public static bool IsCleanText(string value)
    {
        for (var i = 0; i < value.Length;)
        {
            if (Rune.DecodeFromUtf16(value.AsSpan(i), out var rune, out var consumed) != OperationStatus.Done)
                return false;
            if (Rune.IsControl(rune) || IsBidiControl(rune.Value)) return false;
            i += consumed;
        }
        return true;
    }

    private static bool IsBidiControl(int c) =>
        c is 0x061C or 0x200E or 0x200F or (>= 0x202A and <= 0x202E) or (>= 0x2066 and <= 0x2069);

    private static Dictionary<string, string> Check(params (string Field, string? Error)[] checks) =>
        checks.Where(c => c.Error is not null).ToDictionary(c => c.Field, c => c.Error!);

    private static void Throw(Dictionary<string, string> errors)
    {
        if (errors.Count > 0) throw new ValidationException(errors);
    }
}
