using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Gatekeeper.Web;

public sealed record WebOptions
{
    /// <summary>A session that has not been used for this long ends.</summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(30);
    /// <summary>A session ends this long after login, however active it is.</summary>
    public TimeSpan AbsoluteTimeout { get; init; } = TimeSpan.FromHours(8);
    public int MaxSessions { get; init; } = 1000;
}

/// <summary>The applications as read at one moment: the ones a client can belong to, and every name.</summary>
public sealed record AppListSnapshot(DateTimeOffset At, List<AppDto> Choices, Dictionary<Guid, string> Names);

/// <summary>The Gatekeeper tokens of one signed-in administrator. Immutable: a refresh swaps the whole record.</summary>
public sealed record Tokens(string Access, DateTimeOffset AccessExpiresAt, string Refresh, DateTimeOffset RefreshExpiresAt);

/// <summary>
/// One signed-in administrator. The browser only ever holds the opaque session id (in an HttpOnly cookie); the access and
/// refresh tokens stay here, on the server.
/// </summary>
public sealed class WebSession(string id, string username, Tokens tokens, DateTimeOffset createdAt)
{
    private Tokens _tokens = tokens;
    private long _lastSeenTicks = createdAt.UtcTicks;

    public string Id { get; } = id;
    public string Username { get; } = username;
    /// <summary>The signed-in user's id: the <c>sub</c> claim of the current access token (null if it cannot be read). Unlike the username it survives a rename.</summary>
    public Guid? UserId => GuidClaim(Tokens.Access, "sub");
    /// <summary>The id of this administrator's API (refresh) session: the <c>sid</c> claim of the access token.</summary>
    public Guid? ApiSessionId => GuidClaim(Tokens.Access, "sid");
    /// <summary>The lifetime of an access token as the operator set it: <c>exp</c> minus <c>iat</c> of this session's token (null if it cannot be read).</summary>
    public TimeSpan? AccessLifetime => Lifetime(Tokens.Access);
    public DateTimeOffset CreatedAt { get; } = createdAt;
    public DateTimeOffset LastSeen => new(Interlocked.Read(ref _lastSeenTicks), TimeSpan.Zero);
    public Tokens Tokens { get => Volatile.Read(ref _tokens); set => Volatile.Write(ref _tokens, value); }
    /// <summary>Held while the tokens are refreshed: refresh tokens rotate, so two parallel refreshes would look like theft.</summary>
    public SemaphoreSlim RefreshLock { get; } = new(1, 1);

    private static Guid? GuidClaim(string jwt, string name) =>
        Payload(jwt, root => root.TryGetProperty(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String && Guid.TryParse(v.GetString(), out var id) ? id : (Guid?)null);

    private static TimeSpan? Lifetime(string jwt) =>
        Payload(jwt, root =>
        {
            if (!root.TryGetProperty("exp", out var exp) || !root.TryGetProperty("iat", out var iat)) return (TimeSpan?)null;
            if (exp.ValueKind != System.Text.Json.JsonValueKind.Number || iat.ValueKind != System.Text.Json.JsonValueKind.Number) return null;
            if (!exp.TryGetInt64(out var e) || !iat.TryGetInt64(out var i)) return null;
            var seconds = e - i;
            return seconds is > 0 and <= 86400 * 365 ? TimeSpan.FromSeconds(seconds) : null;
        });

    private static T? Payload<T>(string jwt, Func<System.Text.Json.JsonElement, T?> read)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length != 3) return default;
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            using var doc = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(payload));
            return doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object ? read(doc.RootElement) : default;
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return default;
        }
    }

    /// <summary>The most recently read application list (see the client pages); a short-lived cache, replaced as a whole.</summary>
    public AppListSnapshot? AppList { get { lock (_appListLock) return _appList; } }
    private readonly object _appListLock = new();
    private AppListSnapshot? _appList;
    private long _appListVersion;

    /// <summary>Forgets the cached list; a read that started before this call will not be stored.</summary>
    public void InvalidateAppList()
    {
        lock (_appListLock)
        {
            _appListVersion++;
            _appList = null;
        }
    }

    /// <summary>The version to hand to <see cref="TryStoreAppList"/>: taken before the list is read.</summary>
    public long AppListVersion { get { lock (_appListLock) return _appListVersion; } }

    /// <summary>Stores a list read since <paramref name="version"/> was taken, unless the list was invalidated meanwhile.</summary>
    public void TryStoreAppList(AppListSnapshot snapshot, long version)
    {
        lock (_appListLock)
            if (version == _appListVersion) _appList = snapshot;
    }

    /// <summary>Drops the cached list if it is the given (expired) one.</summary>
    public void DropAppList(AppListSnapshot expired)
    {
        lock (_appListLock)
            if (ReferenceEquals(_appList, expired)) _appList = null;
    }

    private const int MaxNonces = 32;
    private readonly object _nonceLock = new();
    private readonly List<string> _nonces = [];

    /// <summary>
    /// A random one-time value for a form that must not be submitted twice (it is remembered here, on the server, not in a
    /// cookie). At most 32 are kept; the oldest is forgotten first.
    /// </summary>
    public string IssueNonce(string purpose)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');
        lock (_nonceLock)
        {
            _nonces.Add(purpose + "|" + nonce);
            if (_nonces.Count > MaxNonces) _nonces.RemoveRange(0, _nonces.Count - MaxNonces);
        }
        return nonce;
    }

    /// <summary>Uses a nonce up: true for exactly one caller, even when several submit the same one at once.</summary>
    public bool ConsumeNonce(string purpose, string? nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length > 64) return false;
        lock (_nonceLock) return _nonces.Remove(purpose + "|" + nonce);
    }

    internal void Touch(DateTimeOffset now) => Interlocked.Exchange(ref _lastSeenTicks, now.UtcTicks);
}

/// <summary>In-memory server-side sessions, looked up by a SHA-256 of the cookie value. A restart signs everyone out.</summary>
public sealed class WebSessions(TimeProvider time, WebOptions? options = null)
{
    private readonly WebOptions _options = options ?? new WebOptions();
    private readonly ConcurrentDictionary<string, WebSession> _sessions = new();
    private long _lastSweepTicks;

    public int Count => _sessions.Count;

    public WebSession Create(string username, Tokens tokens)
    {
        var now = time.GetUtcNow();
        Sweep(now);
        if (_sessions.Count >= _options.MaxSessions)
            foreach (var oldest in _sessions.Values.OrderBy(s => s.LastSeen).Take(Math.Max(1, _sessions.Count - _options.MaxSessions + 1)).ToList())
                Remove(oldest.Id);
        var id = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var session = new WebSession(id, username, tokens, now);
        _sessions[Key(id)] = session;
        return session;
    }

    /// <summary>The live session for a cookie value (and counts the request as activity), or null.</summary>
    public WebSession? Find(string? id)
    {
        if (string.IsNullOrEmpty(id) || id.Length > 64) return null;
        if (!_sessions.TryGetValue(Key(id), out var s)) return null;
        var now = time.GetUtcNow();
        if (Expired(s, now)) { Remove(id); return null; }
        s.Touch(now);
        Sweep(now);
        return s;
    }

    /// <summary>Drops a session and returns it (null if there was none).</summary>
    public WebSession? Remove(string? id) =>
        !string.IsNullOrEmpty(id) && id.Length <= 64 && _sessions.TryRemove(Key(id), out var s) ? s : null;

    private bool Expired(WebSession s, DateTimeOffset now) =>
        now - s.LastSeen > _options.IdleTimeout || now - s.CreatedAt > _options.AbsoluteTimeout || s.Tokens.RefreshExpiresAt <= now;

    private void Sweep(DateTimeOffset now)
    {
        var last = Interlocked.Read(ref _lastSweepTicks);
        if (now.UtcTicks - last < TimeSpan.TicksPerSecond * 30 || Interlocked.CompareExchange(ref _lastSweepTicks, now.UtcTicks, last) != last) return;
        foreach (var (key, s) in _sessions)
            if (Expired(s, now)) _sessions.TryRemove(key, out _);
    }

    private static string Key(string id) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id)));
}
