using System.Net;

namespace Gatekeeper.Api;

/// <summary>
/// Logs one warning (at most once per interval, per peer address, per process) when a request carries <c>X-Forwarded-For</c> from a peer
/// that is not in <c>Auth__TrustedProxies</c>: the header is then ignored, so every caller behind that peer shares one throttle bucket.
/// At most <see cref="MaxPeers"/> peers are remembered (entries past their interval are reused); when the table is full, new peers are
/// dropped silently. Only the peer address is logged, never the header (it is caller-controlled).
/// </summary>
public sealed class ForwardedHeaderWarning(IReadOnlyCollection<IPAddress> trusted, TimeProvider? time = null, TimeSpan? interval = null)
{
    public const int MaxPeers = 16;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromHours(1);
    private readonly object _lock = new();
    private readonly Dictionary<string, long> _last = [];

    /// <summary>The peer to name in the warning when one is due now (and marks it as logged); otherwise null.</summary>
    public string? Check(IPAddress? peer, bool hasForwardedFor)
    {
        if (!hasForwardedFor) return null;
        var normal = peer is { IsIPv4MappedToIPv6: true } ? peer.MapToIPv4() : peer;
        if (normal is not null && trusted.Any(t => t.Equals(normal))) return null;
        var key = normal?.ToString() ?? "unknown";
        var now = _time.GetUtcNow().UtcTicks;
        lock (_lock)
        {
            if (_last.TryGetValue(key, out var last))
            {
                if (now - last < _interval.Ticks) return null;
            }
            else if (_last.Count >= MaxPeers)
            {
                foreach (var old in _last.Where(e => now - e.Value >= _interval.Ticks).Select(e => e.Key).ToList()) _last.Remove(old);
                if (_last.Count >= MaxPeers) return null;
            }
            _last[key] = now;
            return key;
        }
    }
}
