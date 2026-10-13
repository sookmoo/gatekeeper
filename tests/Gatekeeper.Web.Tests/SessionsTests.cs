using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Web.Tests;

public class SessionsTests
{
    private static Tokens T(FakeTimeProvider t) => new("a", t.GetUtcNow().AddMinutes(15), "r", t.GetUtcNow().AddDays(30));

    [Fact]
    public void A_session_is_found_by_its_id_only_and_ids_are_random()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time);
        var a = s.Create("alice", T(time));
        var b = s.Create("alice", T(time));
        Assert.NotEqual(a.Id, b.Id);
        Assert.True(a.Id.Length >= 43);
        Assert.Same(a, s.Find(a.Id));
        Assert.Null(s.Find(a.Id + "x"));
        Assert.Null(s.Find(""));
        Assert.Null(s.Find(null));
        Assert.Null(s.Find(new string('a', 1000)));
        s.Remove(a.Id);
        Assert.Null(s.Find(a.Id));
        Assert.Same(b, s.Find(b.Id));
    }

    [Fact]
    public void Idle_absolute_and_refresh_expiry_each_end_a_session()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { IdleTimeout = TimeSpan.FromMinutes(10), AbsoluteTimeout = TimeSpan.FromHours(1) });
        var idle = s.Create("a", T(time));
        time.Advance(TimeSpan.FromMinutes(11));
        Assert.Null(s.Find(idle.Id));

        var busy = s.Create("b", T(time));
        for (var i = 0; i < 6; i++) { time.Advance(TimeSpan.FromMinutes(9)); Assert.NotNull(s.Find(busy.Id)); }
        time.Advance(TimeSpan.FromMinutes(9));
        Assert.Null(s.Find(busy.Id)); // 63 minutes since creation

        var shortRefresh = s.Create("c", new Tokens("a", time.GetUtcNow().AddMinutes(15), "r", time.GetUtcNow().AddMinutes(5)));
        time.Advance(TimeSpan.FromMinutes(6));
        Assert.Null(s.Find(shortRefresh.Id));
    }

    [Fact]
    public void The_number_of_sessions_is_bounded_and_the_least_recently_used_go_first()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3 });
        var first = s.Create("a", T(time)); time.Advance(TimeSpan.FromSeconds(1));
        var second = s.Create("b", T(time)); time.Advance(TimeSpan.FromSeconds(1));
        var third = s.Create("c", T(time)); time.Advance(TimeSpan.FromSeconds(1));
        s.Find(first.Id); time.Advance(TimeSpan.FromSeconds(1));
        s.Create("d", T(time));
        Assert.Equal(3, s.Count);
        Assert.Null(s.Find(second.Id));
        Assert.NotNull(s.Find(first.Id));
        Assert.NotNull(s.Find(third.Id));
    }

    [Fact]
    public void The_failure_throttle_blocks_per_address_expires_and_stays_bounded()
    {
        var time = new FakeTimeProvider();
        var t = new FailureThrottle(time, maxFailures: 3, window: TimeSpan.FromMinutes(10), maxEntries: 5);
        for (var i = 0; i < 3; i++) t.RecordFailure("1.1.1.1");
        Assert.True(t.IsBlocked("1.1.1.1", out var wait));
        Assert.InRange(wait, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10));
        Assert.False(t.IsBlocked("2.2.2.2", out _));
        t.RecordSuccess("1.1.1.1");
        Assert.False(t.IsBlocked("1.1.1.1", out _));
        for (var i = 0; i < 3; i++) t.RecordFailure("1.1.1.1");
        time.Advance(TimeSpan.FromMinutes(11));
        Assert.False(t.IsBlocked("1.1.1.1", out _));
        for (var i = 0; i < 50; i++) t.RecordFailure($"10.0.0.{i}"); // a flood of addresses cannot grow it past the bound
        for (var i = 0; i < 3; i++) t.RecordFailure("9.9.9.9");
        Assert.True(t.IsBlocked("9.9.9.9", out _));
    }
}
