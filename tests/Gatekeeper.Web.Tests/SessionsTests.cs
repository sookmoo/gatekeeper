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
    public void One_user_signing_in_many_times_only_ends_their_own_oldest_sessions()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 100, MaxSessionsPerUser = 2 });
        var bob = s.Create("bob", T(time)); time.Advance(TimeSpan.FromSeconds(1));
        var a1 = s.Create("alice", T(time)); time.Advance(TimeSpan.FromSeconds(1));
        var a2 = s.Create("Alice", T(time)); time.Advance(TimeSpan.FromSeconds(1)); // same user, other case
        var a3 = s.Create("alice", T(time));
        Assert.Null(s.Find(a1.Id));
        Assert.NotNull(s.Find(a2.Id));
        Assert.NotNull(s.Find(a3.Id));
        for (var i = 0; i < 20; i++) { time.Advance(TimeSpan.FromSeconds(1)); s.Create("alice", T(time)); }
        Assert.NotNull(s.Find(bob.Id)); // never evicted by someone else's sign-ins
        Assert.Equal(3, s.Count);
    }

    [Fact]
    public void A_full_table_refuses_new_sign_ins_instead_of_ending_other_sessions_but_reclaims_expired_ones()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, MaxSessionsPerUser = 5, IdleTimeout = TimeSpan.FromMinutes(30) });
        var one = s.Create("a", T(time)); var two = s.Create("b", T(time)); var three = s.Create("c", T(time));
        Assert.Throws<WebSessionLimitException>(() => s.Create("d", T(time)));
        Assert.NotNull(s.Find(one.Id)); Assert.NotNull(s.Find(two.Id)); Assert.NotNull(s.Find(three.Id));
        Assert.Equal(3, s.Count);
        time.Advance(TimeSpan.FromMinutes(31)); // all idle past the timeout: reclaimable
        Assert.NotNull(s.Create("d", T(time)));
        Assert.Equal(1, s.Count);
    }

    [Fact]
    public void A_user_signing_in_again_at_a_full_table_makes_room_with_their_own_oldest_session()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 2, MaxSessionsPerUser = 1 });
        var mine = s.Create("a", T(time)); time.Advance(TimeSpan.FromSeconds(1));
        var theirs = s.Create("b", T(time));
        var evicted = new List<WebSession>();
        var again = s.Create("a", T(time), evicted);
        Assert.Equal([mine], evicted);
        Assert.Null(s.Find(mine.Id));
        Assert.NotNull(s.Find(theirs.Id));
        Assert.NotNull(s.Find(again.Id));
        // Someone new is still refused and nothing is evicted for them.
        Assert.Throws<WebSessionLimitException>(() => s.Create("c", T(time), evicted));
        Assert.Equal(2, s.Count);
    }

    [Fact]
    public void The_throttle_blocks_a_pair_then_an_address_and_a_success_clears_only_its_own_pair()
    {
        var time = new FakeTimeProvider();
        var t = new FailureThrottle(time, maxPerPair: 3, maxPerAddress: 8, window: TimeSpan.FromMinutes(10), maxEntries: 50);
        for (var i = 0; i < 3; i++) t.RecordFailure("1.1.1.1", "Alice");
        Assert.True(t.IsBlocked("1.1.1.1", "alice", out var wait)); // case-insensitive
        Assert.InRange(wait, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10));
        Assert.False(t.IsBlocked("1.1.1.1", "bob", out _));          // another account from the same address is fine
        Assert.False(t.IsBlocked("2.2.2.2", "alice", out _));        // the owner elsewhere is never locked out

        t.RecordSuccess("1.1.1.1", "alice");
        Assert.False(t.IsBlocked("1.1.1.1", "alice", out _));

        for (var i = 0; i < 8; i++) t.RecordFailure("3.3.3.3", $"user{i}"); // spread over names: the address limit applies
        Assert.True(t.IsBlocked("3.3.3.3", "someone-new", out _));
        t.RecordSuccess("3.3.3.3", "user1");
        Assert.True(t.IsBlocked("3.3.3.3", "someone-new", out _)); // a success never resets the address counter
        time.Advance(TimeSpan.FromMinutes(11));
        Assert.False(t.IsBlocked("3.3.3.3", "someone-new", out _));
    }

    [Fact]
    public void The_throttle_buckets_ipv6_by_64_ignores_odd_names_and_stays_bounded()
    {
        var time = new FakeTimeProvider();
        var t = new FailureThrottle(time, maxPerPair: 100, maxPerAddress: 3, maxEntries: 10);
        t.RecordFailure("2001:db8:1:2:aaaa::1", "a");
        t.RecordFailure("2001:db8:1:2:bbbb::2", "b");
        t.RecordFailure("2001:db8:1:2:cccc::3", "c");
        Assert.True(t.IsBlocked("2001:db8:1:2:dddd::4", "d", out _));
        Assert.False(t.IsBlocked("2001:db8:1:3::1", "d", out _));
        for (var i = 0; i < 3; i++) t.RecordFailure("::ffff:198.51.100.7", "x");
        Assert.True(t.IsBlocked("198.51.100.7", "y", out _)); // mapped IPv4 is the same as IPv4

        var huge = new string('x', 5_000_000);
        for (var i = 0; i < 3; i++) t.RecordFailure("9.9.9.9", huge); // counts against the address only
        Assert.True(t.IsBlocked("9.9.9.9", huge, out _));
        for (var i = 0; i < 200; i++) { time.Advance(TimeSpan.FromMilliseconds(1)); t.RecordFailure($"10.0.{i / 250}.{i % 250}", $"u{i}"); } // a flood cannot grow it past the bound
        for (var i = 0; i < 3; i++) t.RecordFailure("203.0.113.9", "someone");
        Assert.True(t.IsBlocked("203.0.113.9", "someone", out _));
    }
}
