extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent verification of slice 5f (and of crafted POSTs to the list pages of 5a-5e).</summary>
public class Sessions5fQaTests : IClassFixture<WebFixture>
{
    private const string Password = "a long enough password";
    private readonly WebFixture _f;

    public Sessions5fQaTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<HttpClient> ApiAdminAsync(WebFixture f)
    {
        var c = f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private static async Task<Guid> IdOf(HttpResponseMessage r)
    {
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<(Guid User, string UserName, string AppName)> UserWithAppAsync(HttpClient api, TimeSpan? testLifetime = null)
    {
        var name = Unique("qus");
        var user = await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = testLifetime is null ? "person" : "test", expiresAt = testLifetime is { } l ? DateTimeOffset.UtcNow + l : (DateTimeOffset?)null }));
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{user}/password", new { password = Password })).StatusCode);
        var appName = Unique("qapp");
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = appName }));
        var role = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "r", description = "d" }));
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{user}/roles/{role}", null)).StatusCode);
        return (user, name, appName);
    }

    private static async Task<Guid> StartSessionAsync(WebFixture f, string user, string app)
    {
        var r = await f.Api.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var refresh = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;
        var part = refresh["gkr_".Length..refresh.IndexOf('.')].Replace('-', '+').Replace('_', '/');
        return new Guid(Convert.FromBase64String(part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=')));
    }

    private static async Task<List<Guid>> ApiSessionsAsync(HttpClient api, Guid user) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions?limit=200")).GetProperty("items").EnumerateArray().Select(s => s.GetProperty("id").GetGuid()).ToList();

    private static async Task<Guid> AdminIdAsync(HttpClient api) =>
        (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetGuid();

    private static HttpResponseMessage Json(object o) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(o), System.Text.Encoding.UTF8, "application/json") };

    private static object Row(Guid id, Guid uid, Guid appId, DateTimeOffset when, DateTimeOffset? revoked = null, DateTimeOffset? expires = null) =>
        new { id, userId = uid, appId, createdAt = when, lastUsedAt = when, expiresAt = expires ?? when.AddDays(1), revokedAt = revoked };

    // ---- the developer's claim: a crafted POST to a list page is a 500 ----

    [Theory]
    [InlineData("/Users/{u}/Roles")]
    [InlineData("/Users/{u}/Sessions")]
    [InlineData("/Users")]
    [InlineData("/Applications")]
    [InlineData("/Applications/{a}/Roles")]
    [InlineData("/")]
    public async Task A_crafted_post_to_a_list_page_is_never_a_server_error(string template)
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, _, _) = await UserWithAppAsync(api);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("lapp") }));
        var path = template.Replace("{u}", user.ToString()).Replace("{a}", app.ToString());
        var post = await WebFixture.PostFormAsync(b, path, new(), "/Users/" + user + "/Password");
        Assert.True((int)post.StatusCode < 500, $"POST {path} -> {(int)post.StatusCode}");
    }

    // ---- ownership, 50-page cap ----

    [Fact]
    public async Task Revoke_asks_the_scoped_route_without_walking_the_list_and_revoke_all_still_fails_closed_with_a_lower_bound()
    {
        var uid = Guid.Empty;
        var app = Guid.NewGuid();
        var target = Guid.NewGuid();
        var deletes = new List<string>();
        var listCalls = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method == HttpMethod.Delete && path.Contains("ssions")) { deletes.Add(path); return Json(new { revoked = 7 }); }
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions/{target}")) return new HttpResponseMessage(HttpStatusCode.NotFound);
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions"))
            {
                Interlocked.Increment(ref listCalls);
                return Json(new { items = new[] { Row(Guid.NewGuid(), uid, app, DateTimeOffset.UtcNow) }, nextCursor = "more" });
            }
            if (r.Method == HttpMethod.Get && path.EndsWith($"/applications/{app}")) return Json(new { id = app, name = "x" });
            return null;
        })));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        uid = (await UserWithAppAsync(api)).User;

        listCalls = 0;
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{uid}/Sessions/Revoke/{target}")).StatusCode);
        Assert.Equal(0, listCalls); // no list walk: the API answers for the one session
        var post = await WebFixture.PostFormAsync(b, $"/Users/{uid}/Sessions/Revoke/{target}", new(), $"/Users/{uid}/Sessions/RevokeAll");
        Assert.Equal(HttpStatusCode.NotFound, post.StatusCode);
        Assert.Empty(deletes); // never acted on

        listCalls = 0;
        var all = await b.GetStringAsync($"/Users/{uid}/Sessions/RevokeAll");
        Assert.Contains("or more", all);
        Assert.Equal(50, listCalls); // revoke all is still bounded
    }

    [Fact]
    public async Task A_session_beyond_the_first_page_is_revoked_through_the_scoped_route()
    {
        var uid = Guid.Empty;
        var app = Guid.NewGuid();
        var wanted = Guid.NewGuid();
        var deleted = new List<string>();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method == HttpMethod.Delete && path.StartsWith("/v1/users/")) { deleted.Add(path); return new HttpResponseMessage(HttpStatusCode.NoContent); }
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions/{wanted}")) return Json(Row(wanted, uid, app, DateTimeOffset.UtcNow));
            if (r.Method == HttpMethod.Get && path.EndsWith($"/applications/{app}")) return Json(new { id = app, name = "x" });
            return null;
        })));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        uid = (await UserWithAppAsync(api)).User;
        var r = await WebFixture.PostFormAsync(b, $"/Users/{uid}/Sessions/Revoke/{wanted}", new());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal([$"/v1/users/{uid}/sessions/{wanted}"], deleted);
    }

    [Fact]
    public async Task A_session_listed_as_revoked_or_expired_gets_no_revoke_link_and_zero_active_count()
    {
        var uid = Guid.Empty;
        var app = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var a = Guid.NewGuid();
        var c = Guid.NewGuid();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions"))
                return Json(new { items = new[] { Row(a, uid, app, now.AddDays(-2), revoked: now.AddDays(-1)), Row(c, uid, app, now.AddDays(-2), expires: now.AddDays(-1)) }, nextCursor = (string?)null });
            if (r.Method == HttpMethod.Get && path.EndsWith($"/applications/{app}")) return Json(new { id = app, name = "x" });
            return null;
        })));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        uid = (await UserWithAppAsync(api)).User;
        var html = await b.GetStringAsync($"/Users/{uid}/Sessions");
        Assert.Contains("revoked", html);
        Assert.Contains("expired", html);
        Assert.DoesNotContain("Sessions/Revoke/", html);
        Assert.Contains("no active sessions", await b.GetStringAsync($"/Users/{uid}/Sessions/RevokeAll"));
    }

    // ---- 20-session cap ----

    [Fact]
    public async Task The_page_shows_only_the_20_sessions_the_api_keeps_and_revoke_all_counts_20()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, name, appName) = await UserWithAppAsync(api);
        var first = await StartSessionAsync(_f, name, appName);
        for (var i = 0; i < 22; i++) await StartSessionAsync(_f, name, appName);
        var kept = await ApiSessionsAsync(api, user);
        Assert.Equal(20, kept.Count);
        Assert.DoesNotContain(first, kept);

        var html = await b.GetStringAsync($"/Users/{user}/Sessions");
        Assert.Equal(20, Regex.Matches(html, "Sessions/Revoke/").Count);
        Assert.DoesNotContain($"Revoke/{first}", html);
        Assert.DoesNotContain("Next page", html);
        Assert.Contains("Revoke all 20 active sessions", await b.GetStringAsync($"/Users/{user}/Sessions/RevokeAll"));
        // the trimmed one is not reachable through the UI either
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{user}/Sessions/Revoke/{first}")).StatusCode);
    }

    // ---- expired user ----

    [Fact]
    public async Task Sessions_of_an_expired_user_are_empty_and_the_pages_still_work()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, name, appName) = await UserWithAppAsync(api, TimeSpan.FromHours(1));
        var sid = await StartSessionAsync(_f, name, appName);
        // Expire the account and its session without waiting: the API runs on the real clock, so move both ends into the past in the store.
        var sessions = _f.Api.Services.GetRequiredService<Gatekeeper.Application.ISessionRepository>();
        var started = (await sessions.GetAsync(sid))!;
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/sessions/{sid}")).StatusCode);
        var past = DateTimeOffset.UtcNow.AddMinutes(-1);
        await sessions.AddAsync(started with { Id = Guid.NewGuid(), CreatedAt = past.AddHours(-1), LastUsedAt = past.AddHours(-1), ExpiresAt = past, RevokedAt = null }, "unused-hash");
        var users = _f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();
        await users.UpdateAsync((await users.GetAsync(user))! with { ExpiresAt = past });
        Assert.Empty(await ApiSessionsAsync(api, user));
        var list = await b.GetAsync($"/Users/{user}/Sessions");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        Assert.Contains("No active sessions.", await list.Content.ReadAsStringAsync());
        Assert.Contains("no active sessions", await b.GetStringAsync($"/Users/{user}/Sessions/RevokeAll"));
    }

    // ---- revoke-all zero and count cases ----

    [Fact]
    public async Task Revoke_all_with_zero_sessions_offers_no_form_and_a_crafted_post_is_harmless()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, _, _) = await UserWithAppAsync(api);
        var page = await b.GetStringAsync($"/Users/{user}/Sessions/RevokeAll");
        Assert.DoesNotContain("Revoke all</button>", page);
        var post = await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/RevokeAll", new(), $"/Users/{user}/Password");
        Assert.True((int)post.StatusCode < 500, post.StatusCode.ToString());
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode); // own session untouched
    }

    // ---- races ----

    [Fact]
    public async Task A_session_revoked_meanwhile_and_a_double_submit_end_in_404_not_500()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, name, appName) = await UserWithAppAsync(api);
        var s1 = await StartSessionAsync(_f, name, appName);
        var s2 = await StartSessionAsync(_f, name, appName);

        // revoked by someone else between confirmation page and submit
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync($"/Users/{user}/Sessions/Revoke/{s1}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/sessions/{s1}")).StatusCode);
        var late = await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/Revoke/{s1}", new(), $"/Users/{user}/Sessions/Revoke/{s2}");
        Assert.Equal(HttpStatusCode.NotFound, late.StatusCode);

        // double submit
        var token = await WebFixture.TokenAsync(b, $"/Users/{user}/Sessions/Revoke/{s2}");
        var form = () => new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token });
        var first = await b.PostAsync($"/Users/{user}/Sessions/Revoke/{s2}", form());
        var second = await b.PostAsync($"/Users/{user}/Sessions/Revoke/{s2}", form());
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, second.StatusCode);

        // revoke all twice: the second one finds nothing and must not error
        await StartSessionAsync(_f, name, appName);
        var token2 = await WebFixture.TokenAsync(b, $"/Users/{user}/Sessions/RevokeAll");
        var r1 = await b.PostAsync($"/Users/{user}/Sessions/RevokeAll", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token2 }));
        var r2 = await b.PostAsync($"/Users/{user}/Sessions/RevokeAll", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token2 }));
        Assert.Equal(HttpStatusCode.Redirect, r1.StatusCode);
        Assert.True((int)r2.StatusCode < 500, r2.StatusCode.ToString());
    }

    [Fact]
    public async Task Parallel_revokes_of_one_session_never_give_a_server_error()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, name, appName) = await UserWithAppAsync(api);
        var sid = await StartSessionAsync(_f, name, appName);
        var token = await WebFixture.TokenAsync(b, $"/Users/{user}/Sessions/Revoke/{sid}");
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => b.PostAsync($"/Users/{user}/Sessions/Revoke/{sid}",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }))));
        Assert.All(results, r => Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.NotFound, r.StatusCode.ToString()));
        Assert.Empty(await ApiSessionsAsync(api, user));
    }

    // ---- token without sid ----

    [Fact]
    public void A_token_without_a_usable_sid_gives_no_api_session_id()
    {
        static string Jwt(string payload) => "h." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".s";
        WebSession S(string access) => new("id", "u", new Tokens(access, DateTimeOffset.UtcNow, "r", DateTimeOffset.UtcNow), DateTimeOffset.UtcNow);
        var sub = Guid.NewGuid();
        Assert.Null(S(Jwt($"{{\"sub\":\"{sub}\"}}")).ApiSessionId);
        Assert.Equal(sub, S(Jwt($"{{\"sub\":\"{sub}\"}}")).UserId);
        Assert.Null(S(Jwt($"{{\"sub\":\"{sub}\",\"sid\":\"nope\"}}")).ApiSessionId);
        Assert.Null(S(Jwt($"{{\"sub\":\"{sub}\",\"sid\":12}}")).ApiSessionId);
        Assert.Null(S("garbage").ApiSessionId);
        Assert.Null(S("").ApiSessionId);
        var sid = Guid.NewGuid();
        Assert.Equal(sid, S(Jwt($"{{\"sub\":\"{sub}\",\"sid\":\"{sid}\"}}")).ApiSessionId);
    }

    [Fact]
    public async Task Without_a_sid_in_the_ui_token_no_row_is_marked_own_and_revoking_it_still_ends_the_ui_cleanly()
    {
        // The UI is handed a token without sid; its calls to the API carry the real token.
        string? real = null;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new RewritingHandler(f!.Api.Server.CreateHandler(), t => real = t)));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var me = await AdminIdAsync(api);
        var html = await b.GetStringAsync($"/Users/{me}/Sessions");
        Assert.DoesNotContain("your current session", html);
        var id = Guid.Parse(Regex.Match(html, "Revoke/([0-9a-f-]{36})").Groups[1].Value);
        Assert.DoesNotContain("signs you out", await b.GetStringAsync($"/Users/{me}/Sessions/Revoke/{id}"));
        var all = await b.GetStringAsync($"/Users/{me}/Sessions/RevokeAll");
        Assert.Contains("signs you out", all); // revoke-all on oneself does not depend on the sid

        // revoking the real own session unknowingly: the next call must end in sign-in, not an error page
        var post = await WebFixture.PostFormAsync(b, $"/Users/{me}/Sessions/Revoke/{id}", new());
        Assert.True((int)post.StatusCode < 500, post.StatusCode.ToString());
        var next = await b.GetAsync("/Users");
        // Without the sid the UI cannot tell it revoked its own session: the already issued access token keeps working until
        // exp (documented on the page), after which the refresh fails and the user is sent to sign-in. Never an error page.
        Assert.True((int)next.StatusCode < 500, next.StatusCode.ToString());
        if (next.StatusCode != HttpStatusCode.OK) Assert.StartsWith("/Login", next.Headers.Location?.OriginalString);
    }

    private sealed class RewritingHandler(HttpMessageHandler inner, Action<string> captured) : DelegatingHandler(inner)
    {
        private string? _real;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Headers.Authorization is { } auth && _real is not null && auth.Parameter == _fake)
                request.Headers.Authorization = new("Bearer", _real);
            var resp = await base.SendAsync(request, ct);
            if (request.RequestUri!.AbsolutePath.EndsWith("/auth/login") || request.RequestUri.AbsolutePath.EndsWith("/auth/refresh"))
            {
                var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct)).RootElement;
                _real = body.GetProperty("accessToken").GetString();
                captured(_real!);
                // a token that names the real subject but has no sid
                var payload = _real!.Split('.')[1].Replace('-', '+').Replace('_', '/');
                payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
                var claims = JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement;
                var noSid = JsonSerializer.Serialize(new { sub = claims.GetProperty("sub").GetString(), roles = new[] { "admin" } });
                var fake = "e30." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(noSid)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".sig";
                var rewritten = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(await resp.Content.ReadAsStringAsync(ct))!;
                var copy = rewritten.ToDictionary(kv => kv.Key, kv => (object)kv.Value);
                copy["accessToken"] = fake;
                _fake = fake;
                resp.Content = new StringContent(JsonSerializer.Serialize(copy), System.Text.Encoding.UTF8, "application/json");
            }
            return resp;
        }

        private string? _fake;
    }

    // ---- hostile text ----

    [Fact]
    public async Task A_hostile_username_is_encoded_on_all_three_session_pages()
    {
        var hostile = "<img src=x onerror=alert(1)>";
        var uid = Guid.Empty;
        var app = Guid.NewGuid();
        var sid = Guid.NewGuid();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method == HttpMethod.Get && path == $"/v1/users/{uid}")
                return Json(new { id = uid, username = hostile, email = "a@b.c", displayName = hostile, isActive = true, kind = "person", expiresAt = (DateTimeOffset?)null });
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions/{sid}")) return Json(Row(sid, uid, app, DateTimeOffset.UtcNow));
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions"))
                return Json(new { items = new[] { Row(sid, uid, app, DateTimeOffset.UtcNow) }, nextCursor = (string?)null });
            if (r.Method == HttpMethod.Get && path.EndsWith($"/applications/{app}")) return Json(new { id = app, name = hostile });
            return null;
        })));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        uid = (await UserWithAppAsync(api)).User;
        foreach (var p in new[] { $"/Users/{uid}/Sessions", $"/Users/{uid}/Sessions/Revoke/{sid}", $"/Users/{uid}/Sessions/RevokeAll" })
        {
            var html = await b.GetStringAsync(p);
            Assert.DoesNotContain("<img src=x", html);
            Assert.Contains("&lt;img", html);
        }
    }

    // ---- stubbed API errors on the read side ----

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError, 502)]
    [InlineData(HttpStatusCode.ServiceUnavailable, 503)]
    [InlineData(HttpStatusCode.GatewayTimeout, 504)]
    [InlineData(HttpStatusCode.TooManyRequests, 429)]
    [InlineData(HttpStatusCode.Forbidden, 403)]
    [InlineData(HttpStatusCode.NotFound, 404)]
    public async Task Api_errors_on_the_session_list_become_plain_pages_without_the_api_wording(HttpStatusCode api, int expected)
    {
        var uid = Guid.Empty;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath.EndsWith($"/users/{uid}/sessions")
                ? new HttpResponseMessage(api) { Content = new StringContent("{\"detail\":\"secret-internal\"}", System.Text.Encoding.UTF8, "application/json") }
                : null)));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var admin = await ApiAdminAsync(f);
        uid = (await UserWithAppAsync(admin)).User;
        foreach (var p in new[] { $"/Users/{uid}/Sessions", $"/Users/{uid}/Sessions/RevokeAll" })
        {
            var resp = await b.GetAsync(p);
            Assert.Equal(expected, (int)resp.StatusCode);
            Assert.DoesNotContain("secret-internal", await resp.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task A_401_from_the_api_while_revoking_ends_the_ui_session_with_a_redirect()
    {
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            r.Method == HttpMethod.Delete ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : null)));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var admin = await ApiAdminAsync(f);
        var (user, name, appName) = await UserWithAppAsync(admin);
        var sid = await StartSessionAsync(f, name, appName);
        var resp = await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/Revoke/{sid}", new());
        Assert.True(resp.StatusCode is HttpStatusCode.SeeOther or HttpStatusCode.Redirect, resp.StatusCode.ToString());
        Assert.StartsWith("/Login", resp.Headers.Location?.OriginalString);
    }
}
