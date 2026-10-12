using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Api.Tests;

public class LoginThrottleTests
{
    [Fact]
    public void Blocks_after_the_limit_and_recovers_when_the_window_passes()
    {
        var time = new FakeTimeProvider();
        var t = new LoginThrottle(time, maxPerUsername: 3, maxPerAddress: 100, window: TimeSpan.FromMinutes(10));
        for (var i = 0; i < 3; i++) t.RecordFailure("1.2.3.4", "Alice");
        Assert.True(t.IsBlocked("9.9.9.9", "alice", out var wait)); // case-insensitive, different address
        Assert.InRange(wait, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10));
        Assert.False(t.IsBlocked("9.9.9.9", "bob", out _));
        time.Advance(TimeSpan.FromMinutes(11));
        Assert.False(t.IsBlocked("9.9.9.9", "alice", out _));
    }

    [Fact]
    public void Address_limit_applies_across_usernames()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerUsername: 100, maxPerAddress: 3);
        for (var i = 0; i < 3; i++) t.RecordFailure("1.2.3.4", $"user{i}");
        Assert.True(t.IsBlocked("1.2.3.4", "someone-new", out _));
        Assert.False(t.IsBlocked("5.6.7.8", "someone-new", out _));
    }

    [Fact]
    public void Success_clears_the_username_counter()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerUsername: 2, maxPerAddress: 100);
        t.RecordFailure("a", "alice"); t.RecordFailure("a", "alice");
        Assert.True(t.IsBlocked("b", "alice", out _));
        t.RecordSuccess("alice");
        Assert.False(t.IsBlocked("b", "alice", out _));
    }
}
