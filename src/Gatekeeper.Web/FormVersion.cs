using System.Globalization;
using System.Net;

namespace Gatekeeper.Web;

/// <summary>
/// The concurrency token of the edit and delete forms: the hidden "Version" read from the API when the page was opened.
/// It is sent back as <c>If-Match</c>, so a write never overwrites a change made since. A missing or malformed value is
/// refused (the write is never sent without a version).
/// </summary>
public static class FormVersion
{
    public const string ChangedText = "Changed by someone else since you opened it. The current values are shown; apply your change again.";
    public const string MissingText = "The form is out of date or incomplete. The current values are shown; apply your change again.";

    /// <summary>The posted version: exactly one "Version" form value that is a canonical positive integer. Missing or repeated values are refused.</summary>
    public static bool TryRead(HttpRequest request, out long version)
    {
        version = 0;
        if (!request.HasFormContentType) return false;
        var values = request.Form["Version"];
        return values.Count == 1 && TryParse(values[0], out version);
    }

    /// <summary>A positive integer in canonical plain digits (the API starts at 1; no sign, spaces or leading zero); anything else is not a version.</summary>
    public static bool TryParse(string? text, out long version)
    {
        version = 0;
        if (text is null || text.Length is 0 or > 18 || text[0] == '0' || !text.All(char.IsAsciiDigit)) return false;
        return long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out version) && version >= 1;
    }

    /// <summary>The API refused because the resource changed since it was read.</summary>
    public static bool IsStale(ApiException ex) => ex.Status == HttpStatusCode.PreconditionFailed;
}
