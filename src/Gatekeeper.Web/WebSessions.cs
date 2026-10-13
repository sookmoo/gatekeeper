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
    public DateTimeOffset CreatedAt { get; } = createdAt;
    public DateTimeOffset LastSeen => new(Interlocked.Read(ref _lastSeenTicks), TimeSpan.Zero);
    public Tokens Tokens { get => Volatile.Read(ref _tokens); set => Volatile.Write(ref _tokens, value); }
    /// <summary>Held while the tokens are refreshed: refresh tokens rotate, so two parallel refreshes would look like theft.</summary>
    public SemaphoreSlim RefreshLock { get; } = new(1, 1);

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
