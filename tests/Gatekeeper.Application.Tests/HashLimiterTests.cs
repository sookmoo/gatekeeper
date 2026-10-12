using Gatekeeper.Domain;

namespace Gatekeeper.Application.Tests;

public class HashLimiterTests
{
    [Fact]
    public async Task Never_runs_more_than_the_allowed_number_at_once()
    {
        var limiter = new HashLimiter(concurrency: 2, maxQueued: 100);
        int running = 0, peak = 0;
        var tasks = Enumerable.Range(0, 20).Select(_ => limiter.RunAsync(() =>
        {
            var now = Interlocked.Increment(ref running);
            int seen;
            while (now > (seen = Volatile.Read(ref peak))) Interlocked.CompareExchange(ref peak, now, seen);
            Thread.Sleep(20);
            Interlocked.Decrement(ref running);
            return 0;
        }));
        await Task.WhenAll(tasks);
        Assert.InRange(peak, 1, 2);
    }

    [Fact]
    public async Task Rejects_instead_of_queueing_without_bound()
    {
        var limiter = new HashLimiter(concurrency: 1, maxQueued: 1);
        using var release = new ManualResetEventSlim();
        var first = limiter.RunAsync(() => { release.Wait(); return 1; });
        var second = limiter.RunAsync(() => 2);   // queued
        await Assert.ThrowsAsync<BusyException>(() => limiter.RunAsync(() => 3));
        release.Set();
        Assert.Equal(1, await first);
        Assert.Equal(2, await second);
        Assert.Equal(4, await limiter.RunAsync(() => 4)); // recovers
    }
}
