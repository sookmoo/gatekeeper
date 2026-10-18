using System.Globalization;

namespace Gatekeeper.Web.Pages.Users;

/// <summary>Input rules shared by the user pages.</summary>
public static class UserForm
{
    public static readonly string[] Kinds = ["person", "test", "shared"];

    public const string KindText = "Kind must be person, test or shared.";
    public const string ExpiryText = "Expiry must be a date and time in UTC, like 2026-12-31T23:59.";

    private static readonly string[] ExpiryFormats =
    [
        "yyyy-MM-dd'T'HH:mm", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss.FFF",
        "yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss",
    ];

    public static bool IsKind(string? kind) => kind is "person" or "test" or "shared";

    /// <summary>An empty text is no expiry (null). Otherwise exactly a date and time without a zone, which is read as UTC.</summary>
    public static bool TryParseExpiry(string? text, out DateTimeOffset? value)
    {
        value = null;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text)) return true;
        if (!DateTime.TryParseExact(text, ExpiryFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)) return false;
        value = new DateTimeOffset(DateTime.SpecifyKind(parsed, DateTimeKind.Utc));
        return true;
    }

    /// <summary>The expiry as shown in the form field (UTC, whole seconds).</summary>
    public static string FormatExpiry(DateTimeOffset? value) =>
        value is { } v ? v.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) : "";

    /// <summary>The expiry as shown in lists.</summary>
    public static string DisplayExpiry(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";

    /// <summary>The form field shows whole seconds: an entry equal to the stored value in whole seconds is the unchanged value.</summary>
    public static bool SameToTheSecond(DateTimeOffset a, DateTimeOffset? b) =>
        b is { } other && a.UtcTicks / TimeSpan.TicksPerSecond == other.UtcTicks / TimeSpan.TicksPerSecond;
}
