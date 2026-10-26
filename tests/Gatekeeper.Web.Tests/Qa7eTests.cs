using System.Net;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 7e QA: the admin reserve at its edges, how "admin" is decided, races, and the refused sign-in's API session.</summary>
public class Qa7eTests
{
    private static string Jwt(string payload) => "e30." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".sig";
    private static Tokens With(FakeTimeProvider t, string access, int refreshDays = 30) => new(access, t.GetUtcNow().AddMinutes(15), "r", t.GetUtcNow().AddDays(refreshDays));
    private static Tokens User(FakeTimeProvider t) => With(t, "a");
    private static Tokens Admin(FakeTimeProvider t) => With(t, WebFixture.FakeAdminToken());

    [Fact]
    public void Reserve_zero_means_everyone_may_fill_the_table()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 0 });
        for (var i = 0; i < 3; i++) s.Create("u" + i, User(time));
        Assert.Throws<WebSessionLimitException>(() => s.Create("x", User(time)));
        Assert.Throws<WebSessionLimitException>(() => s.Create("boss", Admin(time)));
    }

    [Fact]
    public void Reserve_of_max_minus_one_leaves_one_place_for_non_admins()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 4, AdminReserve = 3, MaxSessionsPerUser = 9 });
        s.Create("u", User(time));
        Assert.Throws<WebSessionLimitException>(() => s.Create("v", User(time)));
        for (var i = 0; i < 3; i++) s.Create("boss" + i, Admin(time));
        Assert.Equal(4, s.Count);
        Assert.Throws<WebSessionLimitException>(() => s.Create("boss9", Admin(time)));
    }

    [Fact]
    public void A_table_over_the_non_admin_limit_still_refuses_non_admins_after_admins_filled_the_reserve_and_one_leaves()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1 });
        var b1 = s.Create("b1", Admin(time)); s.Create("b2", Admin(time)); s.Create("b3", Admin(time)); // admins took everything
        Assert.Throws<WebSessionLimitException>(() => s.Create("u", User(time)));
        s.Remove(b1.Id); // 2 live = limit for non-admins (3 - 1)
        Assert.Throws<WebSessionLimitException>(() => s.Create("u", User(time)));
    }

    [Theory]
    [InlineData("{\"roles\":[\"admin\"]}", true)]
    [InlineData("{\"roles\":\"admin\"}", true)]
    [InlineData("{\"roles\":[\"Admin\"]}", false)]
    [InlineData("{\"roles\":[\"administrator\"]}", false)]
    [InlineData("{\"roles\":[]}", false)]
    [InlineData("{\"roles\":[1]}", false)]
    [InlineData("{\"role\":\"admin\"}", false)]
    [InlineData("{}", false)]
    [InlineData("null", false)]
    [InlineData("[\"admin\"]", false)]
    public void Only_a_roles_claim_with_exactly_admin_counts_as_admin_for_the_reserve(string payload, bool admin)
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 2, AdminReserve = 1 });
        s.Create("u", User(time)); // at the non-admin limit
        var attempt = () => s.Create("x", With(time, Jwt(payload)));
        if (admin) Assert.NotNull(attempt()); else Assert.Throws<WebSessionLimitException>(attempt);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("a.!!!.c")]
    [InlineData("")]
    public void An_unreadable_token_is_not_an_admin(string access)
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 2, AdminReserve = 1 });
        s.Create("u", User(time));
        Assert.Throws<WebSessionLimitException>(() => s.Create("x", With(time, access)));
    }

    [Fact]
    public void Absolute_and_refresh_expiry_are_reclaimed_before_the_reserve_is_counted()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 4, AdminReserve = 2, IdleTimeout = TimeSpan.FromHours(100), AbsoluteTimeout = TimeSpan.FromHours(1) });
        s.Create("a", User(time)); // ends by the absolute timeout
        s.Create("b", new Tokens("a", time.GetUtcNow().AddMinutes(15), "r", time.GetUtcNow().AddMinutes(30))); // ends by its refresh expiry
        Assert.Throws<WebSessionLimitException>(() => s.Create("c", User(time)));
        time.Advance(TimeSpan.FromMinutes(31));
        Assert.NotNull(s.Create("c", User(time))); // b was reclaimed first
        Assert.Equal(2, s.Count);
        Assert.Throws<WebSessionLimitException>(() => s.Create("d", User(time)));
        time.Advance(TimeSpan.FromMinutes(30)); // a is past the absolute timeout; c is not
        Assert.NotNull(s.Create("e", User(time)));
        Assert.Equal(2, s.Count);
    }

    [Fact]
    public void An_admin_replacing_their_own_session_at_a_full_table_keeps_the_count()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1, MaxSessionsPerUser = 1 });
        s.Create("u", User(time));
        var first = s.Create("boss", Admin(time)); s.Create("boss2", Admin(time));
        var evicted = new List<WebSession>();
        s.Create("boss", Admin(time), evicted);
        Assert.Equal([first], evicted);
        Assert.Equal(3, s.Count);
    }

    [Fact]
    public void A_refused_non_admin_evicts_nobody_even_with_surplus_of_their_own_pending_elsewhere()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1, MaxSessionsPerUser = 5 });
        var a = s.Create("a", User(time)); var b = s.Create("b", User(time));
        var evicted = new List<WebSession>();
        Assert.Throws<WebSessionLimitException>(() => s.Create("c", User(time), evicted));
        Assert.Empty(evicted);
        Assert.Same(a, s.Find(a.Id)); Assert.Same(b, s.Find(b.Id));
    }

    [Fact]
    public async Task Racing_sign_ins_never_pass_the_limit_of_their_kind()
    {
        for (var round = 0; round < 20; round++)
        {
            var time = new FakeTimeProvider();
            var s = new WebSessions(time, new WebOptions { MaxSessions = 10, AdminReserve = 4, MaxSessionsPerUser = 100 });
            var created = 0; var refused = 0;
            var tasks = Enumerable.Range(0, 60).Select(i => Task.Run(() =>
            {
                try { s.Create("u" + i, i % 3 == 0 ? Admin(time) : User(time)); Interlocked.Increment(ref created); }
                catch (WebSessionLimitException) { Interlocked.Increment(ref refused); }
            })).ToArray();
            await Task.WhenAll(tasks);
            Assert.Equal(10, s.Count);
            Assert.Equal(10, created);
            Assert.Equal(50, refused);
        }
    }

    [Fact]
    public async Task Racing_non_admins_stop_exactly_at_the_reserve_boundary()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 10, AdminReserve = 4, MaxSessionsPerUser = 100 });
        var ok = 0;
        await Task.WhenAll(Enumerable.Range(0, 50).Select(i => Task.Run(() =>
        {
            try { s.Create("u" + i, User(time)); Interlocked.Increment(ref ok); } catch (WebSessionLimitException) { }
        })));
        Assert.Equal(6, ok);
        for (var i = 0; i < 4; i++) s.Create("boss" + i, Admin(time)); // the reserve is still whole
        Assert.Equal(10, s.Count);
    }

    [Fact]
    public async Task The_refused_non_admin_sign_in_ends_the_api_session_it_started()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sessions = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1 });
        sessions.Create("x", User(time)); sessions.Create("y", User(time));
        var calls = new List<(string Path, string Body)>();
        var api = new GatekeeperApi(new HttpClient(new Handler(calls)) { BaseAddress = new Uri("http://api/") }, sessions, time);
        await Assert.ThrowsAsync<WebSessionLimitException>(() => api.LoginAsync("alice", "pw", CancellationToken.None));
        var logout = Assert.Single(calls, c => c.Path.EndsWith("/auth/logout"));
        Assert.Contains("gkr_new", logout.Body);
        Assert.Equal(2, sessions.Count);
    }

    [Fact]
    public async Task An_admin_sign_in_at_the_same_table_is_admitted_and_nothing_is_logged_out()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sessions = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1 });
        sessions.Create("x", User(time)); sessions.Create("y", User(time));
        var calls = new List<(string Path, string Body)>();
        var api = new GatekeeperApi(new HttpClient(new Handler(calls, WebFixture.FakeAdminToken())) { BaseAddress = new Uri("http://api/") }, sessions, time);
        await api.LoginAsync("boss", "pw", CancellationToken.None);
        Assert.Equal(3, sessions.Count);
        Assert.DoesNotContain(calls, c => c.Path.EndsWith("/auth/logout"));
    }

    private sealed class Handler(List<(string, string)> calls, string access = "a.b.c") : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            calls.Add((request.RequestUri!.AbsolutePath, request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct)));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{{\"accessToken\":\"{access}\",\"expiresIn\":900,\"refreshToken\":\"gkr_new\",\"refreshExpiresIn\":3600}}", System.Text.Encoding.UTF8, "application/json"),
            };
        }
    }
}

public class Qa7eStartupTests
{
    [Theory]
    [InlineData("0", "1")]
    [InlineData("0", "100000")]
    [InlineData("99999", "100000")]
    [InlineData("49", "50")]
    public void Valid_reserves_start(string reserve, string max)
    {
        using var f = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>().WithWebHostBuilder(b => { b.UseSetting("Web:AdminReserve", reserve); b.UseSetting("Web:MaxSessions", max); });
        using var c = f.CreateClient();
    }

    [Theory]
    [InlineData("1", "1")]
    [InlineData("0", "0")]
    [InlineData("100000", "100000")]
    [InlineData("100000", "100001")]
    [InlineData("99999", "99999")]
    [InlineData("50", "50")]
    [InlineData("1.5", "100")]
    [InlineData(" ", "100")]
    [InlineData("99999999999", "100")]
    public void Invalid_reserves_stop_startup(string reserve, string max)
    {
        using var f = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>().WithWebHostBuilder(b => { b.UseSetting("Web:AdminReserve", reserve); b.UseSetting("Web:MaxSessions", max); });
        Assert.Throws<InvalidOperationException>(() => f.CreateClient());
    }
}
