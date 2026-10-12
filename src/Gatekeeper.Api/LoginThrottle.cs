using System.Collections.Concurrent;

namespace Gatekeeper.Api;

/// <summary>
/// First line of defence against password guessing: counts failed logins per client address and per username in a
/// sliding window (in memory, per process). Usernames that do not exist are counted too, so the limit reveals nothing.
/// It is not a substitute for real rate limiting at the edge; behind a proxy every client shares the proxy's address.
/// </summary>
public sealed class LoginThrottle(TimeProvider? time = null, int maxPerUsername = 10, int maxPerAddress = 30, TimeSpan? window = null)
{
    private const int MaxTracked = 50_000;
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _failures = new();

    public bool IsBlocked(string address, string? username, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        var wait = TimeSpan.Zero;
        if (Over($"a:{address}", maxPerAddress, out var w1)) wait = w1;
        if (username is not null && Over($"u:{username.ToLowerInvariant()}", maxPerUsername, out var w2) && w2 > wait) wait = w2;
        retryAfter = wait;
        return wait > TimeSpan.Zero;
    }

    public void RecordFailure(string address, string? username)
    {
        if (_failures.Count > MaxTracked) Sweep();
        if (_failures.Count > MaxTracked) return; // under a flood of distinct keys, stop growing; the address limit still applies
        Add($"a:{address}");
        if (username is not null) Add($"u:{username.ToLowerInvariant()}");
    }

    public void RecordSuccess(string? username)
    {
        if (username is not null) _failures.TryRemove($"u:{username.ToLowerInvariant()}", out _);
    }

    private void Add(string key)
    {
        var q = _failures.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
        lock (q)
        {
            Trim(q);
            q.Enqueue(_time.GetUtcNow());
        }
    }

    private bool Over(string key, int max, out TimeSpan wait)
    {
        wait = TimeSpan.Zero;
        if (!_failures.TryGetValue(key, out var q)) return false;
        lock (q)
        {
            Trim(q);
            if (q.Count < max) return false;
            wait = q.Peek() + _window - _time.GetUtcNow();
            return wait > TimeSpan.Zero;
        }
    }

    private void Trim(Queue<DateTimeOffset> q)
    {
        var cutoff = _time.GetUtcNow() - _window;
        while (q.Count > 0 && q.Peek() <= cutoff) q.Dequeue();
    }

    private void Sweep()
    {
        foreach (var (key, q) in _failures)
        {
            lock (q)
            {
                Trim(q);
                if (q.Count == 0) _failures.TryRemove(key, out _);
            }
        }
    }
}
