using System.Collections.Concurrent;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

/// <summary>
/// First line of defence against password guessing, per process, in a sliding window:
/// <list type="bullet">
/// <item>failures per (client address, username): blocks one attacker from hammering one account without blocking the account's owner elsewhere;</item>
/// <item>failures per client address: blocks one source from spraying many usernames;</item>
/// <item>failures per username across all addresses: never blocks, only lets the caller slow down further attempts.</item>
/// </list>
/// Usernames that do not exist are counted like real ones, so limits reveal nothing. Usernames that cannot be valid are
/// only counted against the address, which keeps memory bounded. Behind a proxy configure trusted proxies so the
/// client address is the real one; otherwise every client shares the proxy's address and its limit.
/// </summary>
public sealed class LoginThrottle(
    TimeProvider? time = null, int maxPerPair = 10, int maxPerAddress = 60, TimeSpan? window = null)
{
    private const int MaxTracked = 50_000;
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _failures = new();
    private long _lastSweepTicks;

    // One IPv6 /64 is a single subscriber's address space, so a client rotating through it must still count as one source.
    private static string Bucket(string address)
    {
        if (!System.Net.IPAddress.TryParse(address, out var ip)) return address;
        if (ip.IsIPv4MappedToIPv6) return ip.MapToIPv4().ToString();
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return ip.ToString();
        var bytes = ip.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new System.Net.IPAddress(bytes) + "/64";
    }

    public bool IsBlocked(string address, string? username, out TimeSpan retryAfter)
    {
        address = Bucket(address);
        var wait = TimeSpan.Zero;
        if (Over($"a:{address}", maxPerAddress, out var w1)) wait = w1;
        if (Key(username) is { } u && Over($"p:{address}|{u}", maxPerPair, out var w2) && w2 > wait) wait = w2;
        retryAfter = wait;
        return wait > TimeSpan.Zero;
    }

    /// <summary>Recent failures counted against the address key itself (for a non-address key such as a session bucket).</summary>
    public int AddressFailures(string address)
    {
        if (!_failures.TryGetValue($"a:{Bucket(address)}", out var q)) return 0;
        lock (q)
        {
            Trim(q);
            return q.Count;
        }
    }

    public void RecordFailure(string address, string? username)
    {
        address = Bucket(address);
        // The address counter is always kept (it is what stops a flood), so it may exceed the cap slightly.
        Add($"a:{address}");
        if (_failures.Count > MaxTracked) SweepAtMostOncePerSecond();
        if (_failures.Count > MaxTracked) return; // full of live keys: stop adding per-account keys, the address limit still applies
        if (Key(username) is { } u)
        {
            Add($"p:{address}|{u}");
            Add($"u:{u}");
        }
    }

    public void RecordSuccess(string address, string? username)
    {
        address = Bucket(address);
        if (Key(username) is { } u) _failures.TryRemove($"p:{address}|{u}", out _);
    }

    /// <summary>Recent failures for the username from any address (for slowing attempts down, never for refusing them).</summary>
    public int UserFailures(string? username)
    {
        if (Key(username) is not { } u || !_failures.TryGetValue($"u:{u}", out var q)) return 0;
        lock (q)
        {
            Trim(q);
            return q.Count;
        }
    }

    private static string? Key(string? username) =>
        Validation.LooksLikeUsername(username) ? username!.ToLowerInvariant() : null;

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

    // A full table must not turn every failed request into an O(n) scan.
    private void SweepAtMostOncePerSecond()
    {
        var now = _time.GetUtcNow().UtcTicks;
        var last = Interlocked.Read(ref _lastSweepTicks);
        if (now - last < TimeSpan.TicksPerSecond || Interlocked.CompareExchange(ref _lastSweepTicks, now, last) != last) return;
        Sweep();
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
