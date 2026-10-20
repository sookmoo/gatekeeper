namespace Gatekeeper.Web;

/// <summary>
/// Reads a checkbox that the form sends as a hidden "false" followed, when ticked, by "true". A browser posts both, so a
/// single bound value would see the first (false). Any "true" means true, otherwise any "false" means false; nothing
/// (or something else) is null: not sent.
/// </summary>
public static class FormFlag
{
    /// <summary>A value that is neither "true" nor "false" (a hand-made POST).</summary>
    public static bool HasInvalid(string[]? values) =>
        values is not null && values.Any(v => !string.Equals(v, "true", StringComparison.OrdinalIgnoreCase) && !string.Equals(v, "false", StringComparison.OrdinalIgnoreCase));

    public static bool? Parse(string[]? values)
    {
        if (values is null) return null;
        if (values.Any(v => string.Equals(v, "true", StringComparison.OrdinalIgnoreCase))) return true;
        return values.Any(v => string.Equals(v, "false", StringComparison.OrdinalIgnoreCase)) ? false : null;
    }
}
