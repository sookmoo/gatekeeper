using Microsoft.AspNetCore.Builder;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6f review: clients behind the Web container are throttled by the address it forwards, only when the API trusts that proxy.</summary>
public class Slice6fThrottleTests
{
    // The test server has no peer address: the test names one in a header and sets it before anything else reads it.
    private sealed class PeerFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, n) =>
            {
                if (ctx.Request.Headers.TryGetValue("X-Test-Peer", out var peer)) ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer.ToString());
                return n();
            });
            next(app);
        };
    }

    private static WebApplicationFactory<Program> Factory(string? trusted) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            if (trusted is not null) b.UseSetting("Auth:TrustedProxies", trusted);
            b.ConfigureServices(s => s.AddTransient<IStartupFilter, PeerFilter>());
        });

    private static async Task<HttpStatusCode> BadLogin(HttpClient c, string peer, string? forwarded, string user = "victim")
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/login") { Content = JsonContent.Create(new { username = user, password = "wrong password here", application = "gatekeeper", refresh = true }) };
        req.Headers.Add("X-Test-Peer", peer);
        if (forwarded is not null) req.Headers.Add("X-Forwarded-For", forwarded);
        return (await c.SendAsync(req)).StatusCode;
    }

    [Fact]
    public async Task Two_clients_behind_a_trusted_web_server_are_throttled_separately()
    {
        using var f = Factory("10.0.0.1");
        var c = f.CreateClient();
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.Unauthorized, await BadLogin(c, "10.0.0.1", "203.0.113.1"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await BadLogin(c, "10.0.0.1", "203.0.113.1"));
        Assert.Equal(HttpStatusCode.Unauthorized, await BadLogin(c, "10.0.0.1", "203.0.113.2")); // another browser, same Web server
    }

    [Fact]
    public async Task The_header_of_an_untrusted_peer_is_ignored()
    {
        using var f = Factory("10.0.0.1");
        var c = f.CreateClient();
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.Unauthorized, await BadLogin(c, "10.0.0.2", "203.0.113." + (i + 1)));
        Assert.Equal(HttpStatusCode.TooManyRequests, await BadLogin(c, "10.0.0.2", "203.0.113.200")); // all counted as 10.0.0.2
    }

    [Fact]
    public async Task With_no_trusted_proxies_the_header_is_ignored_everywhere()
    {
        using var f = Factory(null);
        var c = f.CreateClient();
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.Unauthorized, await BadLogin(c, "10.0.0.1", "203.0.113." + (i + 1)));
        Assert.Equal(HttpStatusCode.TooManyRequests, await BadLogin(c, "10.0.0.1", "203.0.113.99"));
    }

    [Fact]
    public async Task A_forged_first_hop_does_not_escape_the_limit_because_only_the_last_hop_is_taken()
    {
        using var f = Factory("10.0.0.1");
        var c = f.CreateClient();
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.Unauthorized, await BadLogin(c, "10.0.0.1", $"198.51.100.{i + 1}, 203.0.113.1"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await BadLogin(c, "10.0.0.1", "198.51.100.77, 203.0.113.1"));
    }

    private static async Task<(string Refresh, Guid UserId)> Session(HttpClient admin, HttpClient anon)
    {
        var name = $"u{Guid.NewGuid():N}"[..12];
        var id = (await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com" })).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>()).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "correct horse battery" });
        var login = await (await anon.PostAsJsonAsync("/v1/auth/login", new { username = name, password = "correct horse battery", application = "gatekeeper", refresh = true })).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        return (login.GetProperty("refreshToken").GetString()!, id);
    }

    [Fact]
    public async Task A_replayed_dead_session_token_is_throttled_per_session_audited_a_few_times_and_leaves_others_alone()
    {
        using var f = Factory(null);
        var admin = f.CreateAdminClient();
        var anon = f.CreateClient();
        var (dead, id) = await Session(admin, anon);
        var (other, _) = await Session(admin, anon);
        await admin.DeleteAsync($"/v1/users/{id}/sessions");
        for (var i = 0; i < AuthEndpoints.SessionFailuresAllowed; i++) Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = dead })).StatusCode);
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.TooManyRequests, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = dead })).StatusCode);
        // Audit rows: only the first few failures of that session.
        var rows = (await admin.GetFromJsonAsync<System.Text.Json.JsonElement>($"/v1/audit?actor={id}&action=auth.refresh&limit=50")).GetProperty("items").GetArrayLength();
        Assert.Equal(3, rows);
        // Another session, and unproven guesses from this address, are unaffected.
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = other })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = "gkr_nope" })).StatusCode);
    }

    [Fact]
    public async Task Unknown_token_guessing_is_still_counted_per_address()
    {
        using var f = Factory(null);
        var anon = f.CreateClient();
        HttpStatusCode last = default;
        for (var i = 0; i < 70; i++)
            last = (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = "gkr_nope" + i })).StatusCode;
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
    }

    [Theory]
    [InlineData("10")]
    [InlineData("10.0.0.0/24")]
    [InlineData("localhost")]
    public void Shorthand_or_malformed_trusted_proxies_stop_startup(string value)
    {
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseSetting("Auth:TrustedProxies", value));
        Assert.Throws<InvalidOperationException>(() => f.CreateClient());
    }

    [Fact]
    public async Task A_wrong_method_on_a_known_route_answers_405_not_a_policy_refusal_and_unknown_routes_404()
    {
        using var f = Factory(null);
        var anon = f.CreateClient();
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await anon.DeleteAsync("/v1/auth/login")).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await anon.PostAsync("/health", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync("/v1/nothing-here")).StatusCode);
        // Real endpoints are still guarded: a wrong-method request that matches a route's other verbs gets no data and no write.
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/v1/applications")).StatusCode);
    }
}
