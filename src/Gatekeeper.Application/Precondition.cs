using System.Globalization;
using Gatekeeper.Domain;

namespace Gatekeeper.Application;

/// <summary>
/// A parsed <c>If-Match</c> header. <c>*</c> matches any existing row. Otherwise the header is a list of entity-tags and matches
/// when a strong tag equals the row's version (<c>"3"</c>); a weak tag (<c>W/"3"</c>) never matches, because If-Match uses the
/// strong comparison. A well-formed header that matches nothing is a 412, a malformed one is a 400.
/// </summary>
public sealed class Precondition
{
    private const int MaxLength = 1024;

    private readonly bool _any;
    private readonly HashSet<string> _strong;

    private Precondition(bool any, HashSet<string> strong)
    {
        _any = any;
        _strong = strong;
    }

    /// <summary>
    /// Parses the header value (several header lines joined with commas). Throws <see cref="ValidationException"/> (400) if it is malformed.
    /// A single linear pass (no regular expression, so no input can make it slow). Grammar (RFC 9110): <c>*</c>, or a comma-separated list
    /// of <c>[W/]"etagc*"</c> with etagc = %x21 / %x23-7E / %x80-FF; spaces and tabs around elements and empty list elements are ignored,
    /// but at least one tag is required.
    /// </summary>
    public static Precondition Parse(string value)
    {
        if (value.Length > MaxLength) throw Malformed();
        var i = 0;
        SkipBlanks(value, ref i);
        if (i < value.Length && value[i] == '*')
        {
            i++;
            SkipBlanks(value, ref i);
            return i == value.Length ? new Precondition(true, []) : throw Malformed();
        }
        var strong = new HashSet<string>(StringComparer.Ordinal);
        var tags = 0;
        while (true)
        {
            SkipBlanks(value, ref i);
            if (i == value.Length) break;
            if (value[i] == ',') { i++; continue; } // empty list element
            var weak = i + 1 < value.Length && value[i] == 'W' && value[i + 1] == '/';
            if (weak) i += 2;
            if (i == value.Length || value[i] != '"') throw Malformed();
            var start = ++i;
            while (i < value.Length && value[i] != '"')
            {
                var c = value[i];
                if (c != 0x21 && !(c >= 0x23 && c <= 0x7E) && !(c >= 0x80 && c <= 0xFF)) throw Malformed();
                i++;
            }
            if (i == value.Length) throw Malformed(); // no closing quote
            if (!weak) strong.Add(value[start..i]);
            tags++;
            i++;
            SkipBlanks(value, ref i);
            if (i < value.Length && value[i] != ',') throw Malformed();
        }
        return tags > 0 ? new Precondition(false, strong) : throw Malformed();
    }

    private static void SkipBlanks(string value, ref int i)
    {
        while (i < value.Length && (value[i] == ' ' || value[i] == '\t')) i++;
    }

    private static ValidationException Malformed() =>
        new(new Dictionary<string, string> { ["If-Match"] = "must be * or a list of entity-tags such as \"3\"." });

    public bool Matches(long version) => _any || _strong.Contains(version.ToString(CultureInfo.InvariantCulture));

    /// <summary>
    /// Checks the precondition against the version just read and returns the version the write must still find in the store
    /// (null when there is no precondition or it was <c>*</c>: any existing row). Throws <see cref="PreconditionFailedException"/> (412) on a mismatch.
    /// </summary>
    public static long? Require(Precondition? precondition, long currentVersion)
    {
        if (precondition is null) return null;
        if (!precondition.Matches(currentVersion)) throw new PreconditionFailedException();
        return precondition._any ? null : currentVersion;
    }
}
