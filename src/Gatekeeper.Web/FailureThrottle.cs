using System.Net;
using System.Net.Sockets;

namespace Gatekeeper.Web;

/// <summary>
/// Counts failed sign-ins in front of the API's own throttle. Two counters, as in the API: failures per (address, username)
/// block that pair, and failures per address block the address. A success clears only its own pair, so signing in to your own
/// account never resets the guessing counters against someone else's. An unusable username (not a plain name) counts only
/// against the address. IPv6 addresses are bucketed by /64. Bounded: when full, the entry that started earliest is dropped.
/// </summary>
public sealed class FailureThrottle(TimeProvider time, int maxPerPair = 10, int maxPerAddress = 60, TimeSpan? window = null, int maxEntries = 10_000)
{
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(15);
    private readonly Dictionary<string, (int Count, DateTimeOffset Since)> _failures = new();
    private readonly object _gate = new();

    public bool IsBlocked(string address, string? username, out TimeSpan retryAfter)
    {
        lock (_gate)
        {
            var now = time.GetUtcNow();
            var wait = TimeSpan.Zero;
            var blocked = Check("a:" + Bucket(address), maxPerAddress, now, ref wait);
            if (Pair(address, username) is { } pair) blocked |= Check(pair, maxPerPair, now, ref wait);
            retryAfter = blocked ? wait : TimeSpan.Zero;
            return blocked;
        }
    }

    public void RecordFailure(string address, string? username)
    {
        lock (_gate)
        {
            var now = time.GetUtcNow();
            Add("a:" + Bucket(address), now);
            if (Pair(address, username) is { } pair) Add(pair, now);
        }
    }

    public void RecordSuccess(string address, string? username)
    {
        lock (_gate)
        {
            if (Pair(address, username) is { } pair) _failures.Remove(pair);
        }
    }

    private bool Check(string key, int max, DateTimeOffset now, ref TimeSpan wait)
    {
        if (!_failures.TryGetValue(key, out var f)) return false;
        if (now - f.Since >= _window) { _failures.Remove(key); return false; }
        if (f.Count < max) return false;
        var left = f.Since + _window - now;
        if (left > wait) wait = left;
        return true;
    }

    private void Add(string key, DateTimeOffset now)
    {
        if (_failures.TryGetValue(key, out var f) && now - f.Since < _window)
        {
            _failures[key] = (f.Count + 1, f.Since);
            return;
        }
        if (_failures.Count >= maxEntries)
        {
            foreach (var old in _failures.Where(e => now - e.Value.Since >= _window).Select(e => e.Key).ToList()) _failures.Remove(old);
            if (_failures.Count >= maxEntries) _failures.Remove(_failures.MinBy(e => e.Value.Since).Key);
        }
        _failures[key] = (1, now);
    }

    // Only plain names get their own counter: a huge or odd "username" must not cost memory per attempt.
    private static string? Pair(string address, string? username) =>
        username is { Length: > 0 and <= 64 } && username.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '@')
            ? $"p:{Bucket(address)}|{username.ToLowerInvariant()}"
            : null;

    private static string Bucket(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return address.Length <= 64 ? address : address[..64];
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return ip.ToString();
        var bytes = ip.GetAddressBytes();
        Array.Clear(bytes, 8, 8); // the /64 is one subscriber
        return new IPAddress(bytes).ToString() + "/64";
    }
}
