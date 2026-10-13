using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Gatekeeper.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Gatekeeper.Api.Tests;

public class SessionApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public SessionApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<JsonElement> Post(string url, object body)
    {
        var r = await _admin.PostAsJsonAsync(url, body);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private record Person(string Username, Guid UserId, string App, Guid AppId, Guid RoleId);

    private async Task<Person> NewPerson()
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var roleId = (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        var name = Unique("usr");
        var userId = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        return new Person(name, userId, app, appId, roleId);
    }

    private async Task<JsonElement> Login(Person p, bool refresh = true)
    {
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = p.Username, password = Password, application = p.App, refresh });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private Task<HttpResponseMessage> Refresh(string? token) =>
        _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = token });

    [Fact]
    public async Task Refresh_token_is_only_issued_on_request_and_never_for_client_tokens()
    {
        var p = await NewPerson();
        var plain = await Login(p, refresh: false);
        Assert.False(plain.TryGetProperty("refreshToken", out _));
        var with = await Login(p);
        Assert.StartsWith("gkr_", with.GetProperty("refreshToken").GetString());
        Assert.InRange(with.GetProperty("refreshExpiresIn").GetInt32(), 29 * 86400, 30 * 86400);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(with.GetProperty("accessToken").GetString()!);
        Assert.True(jwt.TryGetClaim("sid", out _));
        Assert.False(new JsonWebTokenHandler().ReadJsonWebToken(plain.GetProperty("accessToken").GetString()!).TryGetClaim("sid", out _));
    }

    [Fact]
    public async Task Refresh_rotates_and_replaying_an_old_token_kills_the_session()
    {
        var sessions = _factory.Services.GetRequiredService<SessionService>();
        sessions.ReuseGrace = TimeSpan.Zero; // otherwise an immediate replay counts as a lost race (see the next test)
        try { await ReplayScenario(); } finally { sessions.ReuseGrace = new RefreshOptions().ReuseGrace; }
    }

    private async Task ReplayScenario()
    {
        var p = await NewPerson();
        var first = (await Login(p)).GetProperty("refreshToken").GetString()!;

        var r1 = await Refresh(first);
        Assert.Equal(HttpStatusCode.OK, r1.StatusCode);
        Assert.Equal("no-store", r1.Headers.CacheControl?.ToString());
        var body1 = await r1.Content.ReadFromJsonAsync<JsonElement>();
        var second = body1.GetProperty("refreshToken").GetString()!;
        Assert.NotEqual(first, second);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(body1.GetProperty("accessToken").GetString()!);
        Assert.Equal(p.UserId.ToString(), jwt.Subject);
        Assert.Equal(p.App, jwt.Audiences.Single());
        Assert.Equal(["member"], jwt.Claims.Where(c => c.Type == "roles").Select(c => c.Value));

        var third = (await (await Refresh(second)).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;

        // A token from two rotations ago is simply invalid (it proves nothing and cannot be used to cut a session)...
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(first)).StatusCode);
        // ...but the token that was just replaced coming back means a stale copy exists: the session is cut, newest token included.
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(second)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(third)).StatusCode);
        Assert.Contains("reuse", await _admin.GetStringAsync("/v1/audit?action=auth.refresh&limit=20"));
    }

    [Fact]
    public async Task Parallel_refreshes_of_one_token_leave_exactly_one_winner_and_the_session_alive()
    {
        var p = await NewPerson();
        var first = (await Login(p)).GetProperty("refreshToken").GetString()!;
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Refresh(first)));
        var winners = results.Where(r => r.StatusCode == HttpStatusCode.OK).ToList();
        Assert.Single(winners);
        Assert.All(results.Except(winners), r => Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode));
        // The losers lost a race; they did not cut the session, so the winner's new token still works.
        var next = (await winners[0].Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await Refresh(next)).StatusCode);
    }

    [Fact]
    public async Task Failed_refreshes_never_name_a_user_without_proof_and_do_not_use_the_login_throttle()
    {
        var p = await NewPerson();
        var token = (await Login(p)).GetProperty("refreshToken").GetString()!;
        var sid = token["gkr_".Length..token.IndexOf('.')];
        var forged = $"gkr_{sid}.{new string('A', 43)}";
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(forged)).StatusCode);
        var rows = await _admin.GetStringAsync("/v1/audit?action=auth.refresh&actor=" + p.UserId);
        Assert.DoesNotContain(sid, rows); // the forged attempt is not attributed to the victim or their session

        using var f = _factory.WithWebHostBuilder(_ => { });
        var c = f.CreateClient();
        for (var i = 0; i < 70; i++) await c.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = "gkr_nope" });
        var login = await c.PostAsJsonAsync("/v1/auth/login", new { username = "nobody", password = "wrong password here", application = "gatekeeper" });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode); // refresh failures are counted separately: not 429
    }

    [Fact]
    public async Task A_user_cannot_hold_more_than_the_cap_of_active_sessions()
    {
        var p = await NewPerson();
        var first = (await Login(p)).GetProperty("refreshToken").GetString()!;
        for (var i = 0; i < Gatekeeper.Application.SessionService.MaxActiveSessionsPerUser + 2; i++) await Login(p);
        var list = await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{p.UserId}/sessions?limit=200");
        Assert.Equal(Gatekeeper.Application.SessionService.MaxActiveSessionsPerUser, list.GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(first)).StatusCode); // the oldest one was ended
    }

    [Fact]
    public async Task Every_bad_refresh_token_gets_the_same_401()
    {
        var p = await NewPerson();
        var good = (await Login(p)).GetProperty("refreshToken").GetString()!;
        var bodies = new HashSet<string>();
        foreach (var bad in new string?[] { null, "", "x", "gkr_", "gkr_AAAA.BBBB", good + "x", good[..^2], good.Replace("gkr_", "gkx_"), new string('a', 5000),
                     "gkr_" + Convert.ToBase64String(Guid.NewGuid().ToByteArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".abc" })
        {
            var r = await Refresh(bad);
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            bodies.Add((await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("detail").GetString()!);
        }
        Assert.Single(bodies);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(good)).StatusCode); // the real one was untouched
    }

    [Fact]
    public async Task Logout_ends_the_session_and_is_quiet_about_bad_tokens()
    {
        var p = await NewPerson();
        var login = await Login(p);
        var token = login.GetProperty("refreshToken").GetString()!;
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.NoContent, (await anon.PostAsJsonAsync("/v1/auth/logout", new { refreshToken = "garbage" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(token)).StatusCode); // garbage logout changed nothing
        // The rotated-away token also proves possession, so logout works with a stale copy too.
        Assert.Equal(HttpStatusCode.NoContent, (await anon.PostAsJsonAsync("/v1/auth/logout", new { refreshToken = token })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(token)).StatusCode);
        Assert.Contains("auth.logout", await _admin.GetStringAsync("/v1/audit?action=auth.logout&limit=20"));
    }

    [Fact]
    public async Task Password_change_deactivation_and_role_removal_end_sessions()
    {
        var p = await NewPerson();
        var a = (await Login(p)).GetProperty("refreshToken").GetString()!;
        await _admin.PutAsJsonAsync($"/v1/users/{p.UserId}/password", new { password = "another long password" });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(a)).StatusCode);

        var q = await NewPerson();
        var b = (await Login(q)).GetProperty("refreshToken").GetString()!;
        await _admin.PatchAsJsonAsync($"/v1/users/{q.UserId}", new { isActive = false });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(b)).StatusCode);
        await _admin.PatchAsJsonAsync($"/v1/users/{q.UserId}", new { isActive = true });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(b)).StatusCode); // revoked for good, not merely paused

        var r = await NewPerson();
        var c = (await Login(r)).GetProperty("refreshToken").GetString()!;
        await _admin.DeleteAsync($"/v1/users/{r.UserId}/roles/{r.RoleId}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(c)).StatusCode);

        var s = await NewPerson();
        var d = (await Login(s)).GetProperty("refreshToken").GetString()!;
        await _admin.DeleteAsync($"/v1/applications/{s.AppId}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(d)).StatusCode);
    }

    [Fact]
    public async Task Admins_can_list_and_revoke_sessions()
    {
        var p = await NewPerson();
        var t1 = (await Login(p)).GetProperty("refreshToken").GetString()!;
        var t2 = (await Login(p)).GetProperty("refreshToken").GetString()!;
        var list = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{p.UserId}/sessions")).GetProperty("items");
        Assert.Equal(2, list.GetArrayLength());
        var raw = list.ToString();
        Assert.DoesNotContain("hash", raw.ToLowerInvariant());
        Assert.DoesNotContain(t1, raw);

        var one = list[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/sessions/{one}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/v1/sessions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(1, (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{p.UserId}/sessions")).GetProperty("items").GetArrayLength());

        var all = await _admin.DeleteAsync($"/v1/users/{p.UserId}/sessions");
        Assert.Equal(1, (await all.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(t1)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(t2)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/v1/users/{Guid.NewGuid()}/sessions")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/v1/users/{Guid.NewGuid()}/sessions")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync($"/v1/users/{p.UserId}/sessions")).StatusCode);
    }

    [Fact]
    public async Task An_admin_token_from_a_revoked_session_stops_working_at_once()
    {
        // The management API checks the token's session, so logging out (or revoking) ends admin access without waiting for exp.
        var f = _factory.WithWebHostBuilder(_ => { });
        TestAuth.EnsureAdmin(f);
        var anon = f.CreateClient();
        var login = await (await anon.PostAsJsonAsync("/v1/auth/login",
            new { username = TestAuth.AdminName, password = TestAuth.AdminPassword, application = "gatekeeper", refresh = true })).Content.ReadFromJsonAsync<JsonElement>();
        var c = f.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("accessToken").GetString());
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/v1/applications")).StatusCode);

        await anon.PostAsJsonAsync("/v1/auth/logout", new { refreshToken = login.GetProperty("refreshToken").GetString() });
        await Task.Delay(AdminAccessCheck.CacheFor + TimeSpan.FromSeconds(1)); // the check is cached for a few seconds
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/applications")).StatusCode);
    }

    [Fact]
    public async Task Failed_refreshes_are_throttled()
    {
        using var f = _factory.WithWebHostBuilder(_ => { });
        var c = f.CreateClient();
        HttpStatusCode last = default;
        for (var i = 0; i < 70; i++)
            last = (await c.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = "gkr_nope" })).StatusCode;
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
    }
}
