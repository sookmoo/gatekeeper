extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 6f review: the web session table limits and the forwarded client address.</summary>
public class Account6fReviewTests
{
    private sealed class Recording(List<HttpRequestMessage> seen, Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            seen.Add(request);
            return Task.FromResult(answer(request));
        }
    }

    private static HttpResponseMessage Tokens(int expiresIn) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($"{{\"accessToken\":\"a.b.c\",\"expiresIn\":{expiresIn},\"refreshToken\":\"gkr_x\",\"refreshExpiresIn\":3600}}", System.Text.Encoding.UTF8, "application/json"),
    };

    private static IHttpContextAccessor Accessor(string? address) =>
        new HttpContextAccessor { HttpContext = new DefaultHttpContext { Connection = { RemoteIpAddress = address is null ? null : IPAddress.Parse(address) } } };

    [Fact]
    public async Task Login_and_refresh_forward_the_browsers_address_and_only_that()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var seen = new List<HttpRequestMessage>();
        var api = new GatekeeperApi(new HttpClient(new Recording(seen, r => r.RequestUri!.AbsolutePath.EndsWith("/auth/refresh") ? Tokens(900) : Tokens(1))) { BaseAddress = new Uri("http://api/") },
            new WebSessions(time), time, Accessor("203.0.113.7"));
        var s = await api.LoginAsync("alice", "pw", CancellationToken.None);
        await api.GetMeAsync(s, CancellationToken.None).ContinueWith(_ => { }); // the token is about to expire: a refresh goes first
        var calls = seen.Where(r => r.RequestUri!.AbsolutePath.Contains("/auth/")).ToList();
        Assert.Equal(2, calls.Count);
        Assert.All(calls, r => Assert.Equal(["203.0.113.7"], r.Headers.GetValues("X-Forwarded-For")));
        Assert.All(seen.Where(r => !r.RequestUri!.AbsolutePath.Contains("/auth/")), r => Assert.False(r.Headers.Contains("X-Forwarded-For")));
    }

    [Fact]
    public async Task Without_a_request_address_nothing_is_forwarded()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var seen = new List<HttpRequestMessage>();
        var api = new GatekeeperApi(new HttpClient(new Recording(seen, _ => Tokens(900))) { BaseAddress = new Uri("http://api/") }, new WebSessions(time), time, Accessor(null));
        await api.LoginAsync("alice", "pw", CancellationToken.None);
        Assert.False(seen.Single().Headers.Contains("X-Forwarded-For"));
    }

    [Fact]
    public async Task A_full_session_table_answers_503_at_sign_in_and_signs_nobody_out()
    {
        using var f = new WebFixture(false, s => s.AddSingleton(new WebOptions { MaxSessions = 1 }));
        var first = await f.SignedInAsync();
        var browser = f.Browser();
        var r = await WebFixture.PostFormAsync(browser, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, r.StatusCode);
        Assert.Contains("Too many people are signed in right now.", await r.Content.ReadAsStringAsync());
        Assert.False(r.Headers.TryGetValues("Set-Cookie", out var c) && c.Any(x => x.StartsWith("gk_session=")));
        Assert.Equal(HttpStatusCode.OK, (await first.GetAsync("/Applications")).StatusCode); // the existing session is untouched
        Assert.Equal(1, f.Web.Services.GetRequiredService<WebSessions>().Count);
    }

    [Fact]
    public async Task The_refused_sign_in_ends_the_api_session_it_started()
    {
        using var f = new WebFixture(false, s => s.AddSingleton(new WebOptions { MaxSessions = 1 }));
        await f.SignedInAsync();
        await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        var admin = f.Api.CreateClient();
        var login = await (await admin.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" })).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        admin.DefaultRequestHeaders.Authorization = new("Bearer", login.GetProperty("accessToken").GetString());
        var users = await admin.GetFromJsonAsync<System.Text.Json.JsonElement>($"/v1/users?username={WebFixture.AdminName}");
        var sessions = await admin.GetStringAsync($"/v1/users/{users.GetProperty("items")[0].GetProperty("id").GetGuid()}/sessions");
        Assert.Single(Regex.Matches(sessions, "\"lastUsedAt\""));  // only the one web session; the refused one was ended
    }

    [Fact]
    public async Task A_failing_logout_during_the_refusal_still_ends_in_the_session_limit_not_an_error()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sessions = new WebSessions(time, new WebOptions { MaxSessions = 1 });
        sessions.Create("someone", new Tokens("a", time.GetUtcNow().AddMinutes(5), "r", time.GetUtcNow().AddHours(1)));
        var api = new GatekeeperApi(new HttpClient(new Throwing()) { BaseAddress = new Uri("http://api/") }, sessions, time);
        await Assert.ThrowsAsync<WebSessionLimitException>(() => api.LoginAsync("alice", "pw", CancellationToken.None));
    }

    private sealed class Throwing : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            request.RequestUri!.AbsolutePath.EndsWith("/auth/login") ? Task.FromResult(Tokens(900)) : throw new HttpRequestException("down");
    }

    [Fact]
    public async Task Signing_in_again_at_a_full_table_succeeds_and_ends_the_old_api_session()
    {
        using var f = new WebFixture(false, s => s.AddSingleton(new WebOptions { MaxSessions = 1 }));
        var b = await f.SignedInAsync();
        var again = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword }, "/Applications/Create");
        Assert.Equal(HttpStatusCode.Redirect, again.StatusCode);
        Assert.Equal(1, f.Web.Services.GetRequiredService<WebSessions>().Count);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode);
        var admin = f.Api.CreateClient();
        var login = await (await admin.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" })).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        admin.DefaultRequestHeaders.Authorization = new("Bearer", login.GetProperty("accessToken").GetString());
        var users = await admin.GetFromJsonAsync<System.Text.Json.JsonElement>($"/v1/users?username={WebFixture.AdminName}");
        var sessions = await admin.GetStringAsync($"/v1/users/{users.GetProperty("items")[0].GetProperty("id").GetGuid()}/sessions");
        Assert.Single(Regex.Matches(sessions, "\"lastUsedAt\"")); // the first sign-in's API session was ended
    }
}
