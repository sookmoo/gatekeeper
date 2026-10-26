using System.Net;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 7e review round: a refused sign-in keeps the session the browser came with; the constructor rejects impossible limits.</summary>
public class Review7eTests
{
    private static Tokens With(FakeTimeProvider t, string access) => new(access, t.GetUtcNow().AddMinutes(15), "r", t.GetUtcNow().AddDays(30));
    private static Tokens User(FakeTimeProvider t) => With(t, "a");

    private static Tokens Admin(FakeTimeProvider t) => With(t, WebFixture.FakeAdminToken());

    // Limit for non-admins is 2 (3 - 1); an administrator and the user's own session plus one more admin fill the table to 3.
    private static (WebSessions Sessions, WebSession Mine, WebSession Boss1, WebSession Boss2) FullTable(FakeTimeProvider time)
    {
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1 });
        var mine = s.Create("alice", User(time));
        return (s, mine, s.Create("boss1", Admin(time)), s.Create("boss2", Admin(time)));
    }

    [Fact]
    public void Create_refused_keeps_the_replaced_session_and_evicts_nobody()
    {
        var time = new FakeTimeProvider();
        var (s, mine, boss1, boss2) = FullTable(time);
        var evicted = new List<WebSession>();
        Assert.Throws<WebSessionLimitException>(() => s.Create("alice", User(time), evicted, mine));
        Assert.Empty(evicted);
        Assert.Equal(3, s.Count);
        Assert.Same(mine, s.Find(mine.Id)); Assert.Same(boss1, s.Find(boss1.Id)); Assert.Same(boss2, s.Find(boss2.Id));
    }

    [Fact]
    public void Create_replaces_the_session_only_after_the_check_passes_and_counts_it_as_room()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1 });
        var mine = s.Create("alice", User(time)); var boss = s.Create("boss", Admin(time)); // 2 of 2 for non-admins would be full without the replacement
        var evicted = new List<WebSession>();
        var fresh = s.Create("alice", User(time), evicted, mine);
        Assert.Equal([mine], evicted);
        Assert.Null(s.Find(mine.Id));
        Assert.Same(fresh, s.Find(fresh.Id)); Assert.Same(boss, s.Find(boss.Id));
        Assert.Equal(2, s.Count);
    }

    [Fact]
    public void A_replacing_session_that_is_not_in_the_table_frees_nothing()
    {
        var time = new FakeTimeProvider();
        var (s, mine, _, _) = FullTable(time);
        var ghost = new WebSession("ghost", "z", User(time), time.GetUtcNow());
        var evicted = new List<WebSession>();
        Assert.Throws<WebSessionLimitException>(() => s.Create("z", User(time), evicted, ghost));
        Assert.Empty(evicted);
        Assert.Same(mine, s.Find(mine.Id));
    }

    [Fact]
    public void A_replacing_session_that_is_also_surplus_is_removed_once()
    {
        var time = new FakeTimeProvider();
        var s = new WebSessions(time, new WebOptions { MaxSessions = 10, MaxSessionsPerUser = 1 });
        var mine = s.Create("alice", User(time));
        var evicted = new List<WebSession>();
        s.Create("alice", User(time), evicted, mine);
        Assert.Equal([mine], evicted);
        Assert.Equal(1, s.Count);
    }

    [Fact]
    public async Task A_refused_sign_in_keeps_the_browsers_session_and_ends_only_the_new_api_session()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var (sessions, mine, _, _) = FullTable(time);
        var calls = new List<(string Path, string Body)>();
        var api = new GatekeeperApi(new HttpClient(new Handler(calls)) { BaseAddress = new Uri("http://api/") }, sessions, time);
        await Assert.ThrowsAsync<WebSessionLimitException>(() => api.LoginAsync("alice", "pw", CancellationToken.None, replacing: mine));
        Assert.Same(mine, sessions.Find(mine.Id));
        Assert.Equal(3, sessions.Count);
        var logout = Assert.Single(calls, c => c.Path.EndsWith("/auth/logout"));
        Assert.Contains("gkr_new", logout.Body);
    }

    [Fact]
    public async Task A_successful_sign_in_still_replaces_the_browsers_session_and_ends_its_api_session()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sessions = new WebSessions(time, new WebOptions { MaxSessions = 3, AdminReserve = 1 });
        var mine = sessions.Create("alice", new Tokens("a.b.c", time.GetUtcNow().AddMinutes(15), "gkr_old", time.GetUtcNow().AddDays(1)));
        sessions.Create("boss", Admin(time));
        var calls = new List<(string Path, string Body)>();
        var api = new GatekeeperApi(new HttpClient(new Handler(calls)) { BaseAddress = new Uri("http://api/") }, sessions, time);
        var fresh = await api.LoginAsync("alice", "pw", CancellationToken.None, replacing: mine);
        Assert.Null(sessions.Find(mine.Id));
        Assert.Same(fresh, sessions.Find(fresh.Id));
        Assert.Equal(2, sessions.Count);
        var logout = Assert.Single(calls, c => c.Path.EndsWith("/auth/logout"));
        Assert.Contains("gkr_old", logout.Body);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(-1, 0)]
    [InlineData(5, -1)]
    [InlineData(5, 5)]
    [InlineData(5, 6)]
    public void The_constructor_rejects_impossible_limits(int max, int reserve) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new WebSessions(TimeProvider.System, new WebOptions { MaxSessions = max, AdminReserve = reserve }));

    [Theory]
    [InlineData(1, 0)]
    [InlineData(5, 4)]
    public void The_constructor_accepts_the_edges(int max, int reserve) =>
        Assert.NotNull(new WebSessions(TimeProvider.System, new WebOptions { MaxSessions = max, AdminReserve = reserve }));

    private sealed class Handler(List<(string, string)> calls) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            calls.Add((request.RequestUri!.AbsolutePath, request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct)));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"accessToken\":\"a.b.c\",\"expiresIn\":900,\"refreshToken\":\"gkr_new\",\"refreshExpiresIn\":3600}", System.Text.Encoding.UTF8, "application/json"),
            };
        }
    }
}
