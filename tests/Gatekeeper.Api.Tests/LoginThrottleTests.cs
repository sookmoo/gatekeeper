using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Api.Tests;

public class LoginThrottleTests
{
    [Fact]
    public void One_address_hammering_one_account_is_blocked_but_the_owner_elsewhere_is_not()
    {
        var time = new FakeTimeProvider();
        var t = new LoginThrottle(time, maxPerPair: 3, maxPerAddress: 100, window: TimeSpan.FromMinutes(10));
        for (var i = 0; i < 3; i++) t.RecordFailure("1.2.3.4", "Alice");
        Assert.True(t.IsBlocked("1.2.3.4", "alice", out var wait)); // case-insensitive
        Assert.InRange(wait, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10));
        Assert.False(t.IsBlocked("9.9.9.9", "alice", out _));      // the owner on another address is never locked out
        Assert.False(t.IsBlocked("1.2.3.4", "bob", out _));
        time.Advance(TimeSpan.FromMinutes(11));
        Assert.False(t.IsBlocked("1.2.3.4", "alice", out _));
    }

    [Fact]
    public void A_flood_of_distinct_keys_cannot_switch_the_address_limit_off_and_stays_cheap()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerPair: 100, maxPerAddress: 5);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < 20_000; i++) t.RecordFailure($"10.{i / 65536 % 256}.{i / 256 % 256}.{i % 256}", $"user{i}"); // fills the table
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"flood took {clock.Elapsed}");
        for (var i = 0; i < 5; i++) t.RecordFailure("203.0.113.9", "someone");
        Assert.True(t.IsBlocked("203.0.113.9", "someone", out _));
    }

    [Fact]
    public void An_IPv6_64_is_one_source_and_mapped_IPv4_is_the_same_as_IPv4()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerPair: 100, maxPerAddress: 3);
        t.RecordFailure("2001:db8:1:2:aaaa::1", "a");
        t.RecordFailure("2001:db8:1:2:bbbb::2", "b");
        t.RecordFailure("2001:db8:1:2:cccc::3", "c");
        Assert.True(t.IsBlocked("2001:db8:1:2:dddd::4", "d", out _));
        Assert.False(t.IsBlocked("2001:db8:1:3::1", "d", out _));
        for (var i = 0; i < 3; i++) t.RecordFailure("::ffff:198.51.100.7", "x");
        Assert.True(t.IsBlocked("198.51.100.7", "y", out _));
    }

    [Fact]
    public void Address_limit_applies_across_usernames()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerPair: 100, maxPerAddress: 3);
        for (var i = 0; i < 3; i++) t.RecordFailure("1.2.3.4", $"user{i}");
        Assert.True(t.IsBlocked("1.2.3.4", "someone-new", out _));
        Assert.False(t.IsBlocked("5.6.7.8", "someone-new", out _));
    }

    [Fact]
    public void Success_clears_the_pair_counter()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerPair: 2, maxPerAddress: 100);
        t.RecordFailure("a", "alice"); t.RecordFailure("a", "alice");
        Assert.True(t.IsBlocked("a", "alice", out _));
        t.RecordSuccess("a", "alice");
        Assert.False(t.IsBlocked("a", "alice", out _));
    }

    [Fact]
    public void Failures_across_addresses_count_for_slowing_but_never_block()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerPair: 10, maxPerAddress: 100);
        for (var i = 0; i < 50; i++) t.RecordFailure($"10.0.0.{i}", "alice");
        Assert.Equal(50, t.UserFailures("ALICE"));
        Assert.False(t.IsBlocked("10.9.9.9", "alice", out _));
    }

    [Fact]
    public void Unusable_usernames_only_count_against_the_address_and_cost_no_memory_per_name()
    {
        var t = new LoginThrottle(new FakeTimeProvider(), maxPerPair: 100, maxPerAddress: 3);
        var huge = new string('x', 8_000_000);
        t.RecordFailure("1.1.1.1", huge);
        t.RecordFailure("1.1.1.1", "bad name!");
        t.RecordFailure("1.1.1.1", null);
        Assert.Equal(0, t.UserFailures(huge));
        Assert.True(t.IsBlocked("1.1.1.1", huge, out _));
    }
}
