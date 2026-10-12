using Gatekeeper.Domain;

namespace Gatekeeper.Application;

/// <summary>What a repository fetches: skip <see cref="Offset"/> rows, return at most <see cref="Take"/>.</summary>
public sealed record Slice(int Offset, int Take);

/// <summary>One page of results. <see cref="NextCursor"/> is opaque and null on the last page.</summary>
public sealed record Page<T>(IReadOnlyList<T> Items, string? NextCursor);

/// <summary>A validated paging request. The cursor is opaque to callers (today it encodes an offset).</summary>
public sealed record PageQuery(int Offset, int Limit)
{
    public const int DefaultLimit = 50;
    public const int MaxLimit = 200;
    private const int MaxOffset = 1_000_000;

    public static PageQuery Default { get; } = new(0, DefaultLimit);

    /// <summary>Fetches one extra row so the service can tell whether another page exists.</summary>
    public Slice Slice => new(Offset, Limit + 1);

    public static PageQuery Parse(int? limit, string? cursor)
    {
        var errors = new Dictionary<string, string>();
        if (limit is < 1 or > MaxLimit) errors["limit"] = $"Must be between 1 and {MaxLimit}.";
        var offset = 0;
        if (cursor is not null && !TryDecode(cursor, out offset)) errors["cursor"] = "Invalid cursor.";
        if (errors.Count > 0) throw new ValidationException(errors);
        return new PageQuery(offset, limit ?? DefaultLimit);
    }

    /// <summary>Builds a page from the rows fetched with <see cref="Slice"/> (at most Limit + 1).</summary>
    public Page<T> Build<T>(IReadOnlyList<T> fetched) =>
        fetched.Count > Limit
            ? new Page<T>(fetched.Take(Limit).ToList(), Encode(Offset + Limit))
            : new Page<T>(fetched, null);

    private static string Encode(int offset) =>
        Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes($"o{offset}")).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryDecode(string cursor, out int offset)
    {
        offset = 0;
        if (cursor.Length is 0 or > 32) return false;
        try
        {
            var padded = cursor.Replace('-', '+').Replace('_', '/');
            padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
            var text = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(padded));
            return text.Length > 1 && text[0] == 'o' && text[1..].All(char.IsAsciiDigit)
                   && int.TryParse(text[1..], out offset) && offset is >= 0 and <= MaxOffset
                   && Encode(offset) == cursor; // canonical form only
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
