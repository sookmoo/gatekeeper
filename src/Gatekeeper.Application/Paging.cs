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

/// <summary>The position of an audit row in the newest-first order: rows after it are older, or equal in time with a smaller id.</summary>
public readonly record struct AuditKey(DateTimeOffset At, Guid Id)
{
    /// <summary>The order of ids is that of Postgres <c>uuid</c> (unsigned bytes of the canonical text form), not <see cref="Guid.CompareTo(Guid)"/>.</summary>
    public static int CompareIds(Guid a, Guid b) =>
        a.ToByteArray(bigEndian: true).AsSpan().SequenceCompareTo(b.ToByteArray(bigEndian: true));

    /// <summary>Compares in the list order's key (at, id) ascending; the list itself is the descending order.</summary>
    public static int Compare(AuditKey a, AuditKey b)
    {
        var c = a.At.UtcTicks.CompareTo(b.At.UtcTicks);
        return c != 0 ? c : CompareIds(a.Id, b.Id);
    }
}

/// <summary>
/// A validated paging request for the audit trail. The cursor is a keyset (the last row's time and id): opaque base64url of
/// 'k' + 8 bytes of UTC ticks + 16 bytes of id, canonical form only. Offset cursors of the other lists are refused.
/// </summary>
public sealed record AuditPageQuery(AuditKey? After, int Limit)
{
    public static AuditPageQuery Default { get; } = new(null, PageQuery.DefaultLimit);

    /// <summary>Fetches one extra row so the service can tell whether another page exists.</summary>
    public int Take => Limit + 1;

    public static AuditPageQuery Parse(int? limit, string? cursor)
    {
        var errors = new Dictionary<string, string>();
        if (limit is < 1 or > PageQuery.MaxLimit) errors["limit"] = $"Must be between 1 and {PageQuery.MaxLimit}.";
        AuditKey? after = null;
        if (cursor is not null)
        {
            if (TryDecode(cursor, out var key)) after = key;
            else errors["cursor"] = "Invalid cursor.";
        }
        if (errors.Count > 0) throw new ValidationException(errors);
        return new AuditPageQuery(after, limit ?? PageQuery.DefaultLimit);
    }

    public Page<AuditEvent> Build(IReadOnlyList<AuditEvent> fetched)
    {
        if (fetched.Count <= Limit) return new Page<AuditEvent>(fetched, null);
        var items = fetched.Take(Limit).ToList();
        var last = items[^1];
        return new Page<AuditEvent>(items, Encode(new AuditKey(last.At, last.Id)));
    }

    public static string Encode(AuditKey key)
    {
        var bytes = new byte[25];
        bytes[0] = (byte)'k';
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(1, 8), key.At.UtcTicks);
        key.Id.TryWriteBytes(bytes.AsSpan(9, 16), bigEndian: true, out _);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static bool TryDecode(string cursor, out AuditKey key)
    {
        key = default;
        if (cursor.Length != 34 || !cursor.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return false;
        try
        {
            var bytes = Convert.FromBase64String(cursor.Replace('-', '+').Replace('_', '/') + "==");
            if (bytes.Length != 25 || bytes[0] != (byte)'k') return false;
            var ticks = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(1, 8));
            if (ticks is < 0 or > 3_155_378_975_999_999_999L || ticks % 10 != 0) return false; // DateTime range; stored times are whole microseconds
            key = new AuditKey(new DateTimeOffset(ticks, TimeSpan.Zero), new Guid(bytes.AsSpan(9, 16), bigEndian: true));
            return Encode(key) == cursor; // canonical form only
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
