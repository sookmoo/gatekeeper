namespace Gatekeeper.Web;

/// <summary>
/// Counts failed sign-ins per remote address. A first line of defence in front of the API's own throttle (which, from the API's
/// point of view, sees only this web server's address). Bounded: when full, the entry that started earliest is dropped.
/// </summary>
public sealed class FailureThrottle(TimeProvider time, int maxFailures = 10, TimeSpan? window = null, int maxEntries = 10_000)
{
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(15);
    private readonly Dictionary<string, (int Count, DateTimeOffset Since)> _failures = new();
    private readonly object _gate = new();

    public bool IsBlocked(string address, out TimeSpan retryAfter)
    {
        lock (_gate)
        {
            retryAfter = TimeSpan.Zero;
            if (!_failures.TryGetValue(address, out var f)) return false;
            var now = time.GetUtcNow();
            if (now - f.Since >= _window) { _failures.Remove(address); return false; }
            if (f.Count < maxFailures) return false;
            retryAfter = f.Since + _window - now;
            return true;
        }
    }

    public void RecordFailure(string address)
    {
        lock (_gate)
        {
            var now = time.GetUtcNow();
            if (_failures.TryGetValue(address, out var f) && now - f.Since < _window)
            {
                _failures[address] = (f.Count + 1, f.Since);
                return;
            }
            if (_failures.Count >= maxEntries)
            {
                foreach (var key in _failures.Where(e => now - e.Value.Since >= _window).Select(e => e.Key).ToList()) _failures.Remove(key);
                if (_failures.Count >= maxEntries) _failures.Remove(_failures.MinBy(e => e.Value.Since).Key);
            }
            _failures[address] = (1, now);
        }
    }

    public void RecordSuccess(string address)
    {
        lock (_gate) _failures.Remove(address);
    }
}
