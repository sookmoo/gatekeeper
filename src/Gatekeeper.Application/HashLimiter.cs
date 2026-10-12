using Gatekeeper.Domain;

namespace Gatekeeper.Application;

/// <summary>
/// Caps concurrent password hashing. Argon2 uses tens of MiB and a core per hash, so unbounded parallel logins
/// could exhaust memory and the thread pool. Up to <c>concurrency</c> hashes run at once and a few more wait;
/// beyond that callers get <see cref="BusyException"/> immediately instead of piling up.
/// </summary>
public sealed class HashLimiter(int concurrency = 0, int maxQueued = 0)
{
    private readonly int _concurrency = concurrency > 0 ? concurrency : Math.Clamp(Environment.ProcessorCount, 1, 4);
    private readonly int _maxQueued = maxQueued > 0 ? maxQueued : 8;
    private SemaphoreSlim? _slots;
    private int _pending;

    private SemaphoreSlim Slots => _slots ??= new SemaphoreSlim(_concurrency, _concurrency);

    public async Task<T> RunAsync<T>(Func<T> work, CancellationToken ct = default)
    {
        if (Interlocked.Increment(ref _pending) > _concurrency + _maxQueued)
        {
            Interlocked.Decrement(ref _pending);
            throw new BusyException();
        }
        try
        {
            await Slots.WaitAsync(ct);
            try
            {
                return await Task.Run(work, CancellationToken.None); // never abandon a half-run hash mid-flight
            }
            finally
            {
                Slots.Release();
            }
        }
        finally
        {
            Interlocked.Decrement(ref _pending);
        }
    }
}
