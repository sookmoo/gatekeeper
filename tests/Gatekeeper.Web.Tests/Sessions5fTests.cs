extern alias api;

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Web.Tests;

public class Sessions5fTests : IClassFixture<WebFixture>
{
    private const string Password = "a long enough password";
    private readonly WebFixture _f;

    public Sessions5fTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private sealed class CaptureLog : ILoggerProvider, ILogger
    {
        public ConcurrentQueue<string> Lines { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue(formatter(state, exception) + " " + exception);
    }

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

    /// <summary>A user with a password and a role in a fresh application, plus a function that starts a refresh session for them.</summary>
    private static async Task<(Guid User, string UserName, Guid App, string AppName)> UserWithAppAsync(HttpClient api, TimeSpan? testLifetime = null)
    {
        var name = Unique("sus");
        var user = await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = testLifetime is null ? "person" : "test", expiresAt = testLifetime is { } l ? DateTimeOffset.UtcNow + l : (DateTimeOffset?)null }));
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{user}/password", new { password = Password })).StatusCode);
        var appName = Unique("sapp");
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = appName }));
        var role = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "r", description = "d" }));
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{user}/roles/{role}", null)).StatusCode);
        return (user, name, app, appName);
    }

    private static async Task<(Guid Id, string Refresh)> StartSessionAsync(WebFixture f, string user, string app)
    {
        var r = await f.Api.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        var refresh = body.GetProperty("refreshToken").GetString()!;
        var part = refresh["gkr_".Length..refresh.IndexOf('.')].Replace('-', '+').Replace('_', '/');
        return (new Guid(Convert.FromBase64String(part.PadRight(part.Length + (4 - part.Length % 4) % 4, '='))), refresh);
    }

    private static async Task<List<Guid>> ApiSessionsAsync(HttpClient api, Guid user) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions?limit=200")).GetProperty("items").EnumerateArray().Select(s => s.GetProperty("id").GetGuid()).ToList();

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static async Task<Guid> AdminIdAsync(HttpClient api) =>
        (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetGuid();

    [Fact]
    public async Task Pages_need_a_session_and_posts_need_the_antiforgery_token()
    {
        var anon = _f.Browser();
        var uid = Guid.NewGuid();
        foreach (var path in new[] { $"/Users/{uid}/Sessions", $"/Users/{uid}/Sessions/Revoke/{Guid.NewGuid()}", $"/Users/{uid}/Sessions/RevokeAll" })
        {
            var resp = await anon.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.Equal("/Login", resp.Headers.Location?.OriginalString);
        }

        var api = await ApiAdminAsync(_f);
        var s = await _f.SignedInAsync();
        var (user, name, _, appName) = await UserWithAppAsync(api);
        var (sid, _) = await StartSessionAsync(_f, name, appName);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/{user}/Sessions/Revoke/{sid}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/{user}/Sessions/RevokeAll", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Equal([sid], await ApiSessionsAsync(api, user));
    }

    [Fact]
    public async Task Sessions_are_listed_and_revoked_with_confirmation_one_by_one_and_all()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, name, _, appName) = await UserWithAppAsync(api);
        Assert.Contains("No active sessions.", await b.GetStringAsync($"/Users/{user}/Sessions"));
        var (s1, refresh1) = await StartSessionAsync(_f, name, appName);
        var (s2, _) = await StartSessionAsync(_f, name, appName);
        var (s3, _) = await StartSessionAsync(_f, name, appName);

        var list = await b.GetStringAsync($"/Users/{user}/Sessions");
        Assert.Contains(appName, list);
        Assert.Contains("active", list);
        Assert.Contains("Active sessions of", list);
        Assert.Contains("administration access ends immediately", list);
        Assert.DoesNotContain("up to 15 minutes", list);
        Assert.Contains("Refresh tokens are never shown", list);
        Assert.DoesNotContain(refresh1, list);
        Assert.DoesNotContain("gkr_", list);
        Assert.Contains($"/Users/{user}/Sessions/Revoke/{s1}", list);
        Assert.Contains($"/Users/{user}/Sessions/RevokeAll", list);

        // the confirmation page changes nothing
        var confirm = await b.GetStringAsync($"/Users/{user}/Sessions/Revoke/{s1}");
        Assert.Contains("<button type=\"submit\" class=\"danger\">Revoke</button>", confirm);
        Assert.Contains("administration access ends immediately", confirm);
        Assert.Equal(3, (await ApiSessionsAsync(api, user)).Count);

        var r = await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/Revoke/{s1}", new());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal($"/Users/{user}/Sessions?done=revoked", r.Headers.Location?.OriginalString);
        Assert.Contains("Session revoked.", await b.GetStringAsync(r.Headers.Location!.OriginalString));
        Assert.Equal(HttpStatusCode.Unauthorized, (await _f.Api.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh1 })).StatusCode);
        Assert.Equal(new HashSet<Guid> { s2, s3 }, (await ApiSessionsAsync(api, user)).ToHashSet());
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{user}/Sessions/Revoke/{s1}")).StatusCode); // already gone

        var all = await b.GetStringAsync($"/Users/{user}/Sessions/RevokeAll");
        Assert.Contains("Revoke all 2 active sessions", all);
        Assert.Equal(2, (await ApiSessionsAsync(api, user)).Count);
        var r2 = await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/RevokeAll", new());
        Assert.Equal($"/Users/{user}/Sessions?done=revokedall&n=2", r2.Headers.Location?.OriginalString);
        Assert.Empty(await ApiSessionsAsync(api, user));
        Assert.Contains("2 sessions revoked.", await b.GetStringAsync(r2.Headers.Location!.OriginalString));
        Assert.Contains("no active sessions", await b.GetStringAsync($"/Users/{user}/Sessions/RevokeAll"));
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync($"/Users/{user}/Sessions?done=<script>")).StatusCode);
        Assert.Contains("No sessions were active.", await b.GetStringAsync($"/Users/{user}/Sessions?done=revokedall&n=0"));
        Assert.Contains("3 sessions revoked.", await b.GetStringAsync($"/Users/{user}/Sessions?done=revokedall&n=3"));
        foreach (var bad in new[] { "-1", "x", "1e3", "99999999999", "<b>", "" })
        {
            var page = await b.GetStringAsync($"/Users/{user}/Sessions?done=revokedall&n=" + Uri.EscapeDataString(bad));
            Assert.DoesNotContain("revoked.", page);
            Assert.DoesNotContain("were active", page);
        }
    }

    [Fact]
    public async Task A_session_of_another_user_or_an_unknown_id_is_a_404_and_never_acted_on()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (userA, _, _, _) = await UserWithAppAsync(api);
        var (userB, nameB, _, appB) = await UserWithAppAsync(api);
        var (sidB, _) = await StartSessionAsync(_f, nameB, appB);

        foreach (var path in new[] { $"/Users/{userA}/Sessions/Revoke/{sidB}", $"/Users/{userA}/Sessions/Revoke/{Guid.NewGuid()}", $"/Users/{Guid.NewGuid()}/Sessions/Revoke/{sidB}", $"/Users/{userA}/Sessions/Revoke/not-a-guid", $"/Users/not-a-guid/Sessions", $"/Users/{Guid.NewGuid()}/Sessions", $"/Users/{Guid.NewGuid()}/Sessions/RevokeAll" })
        {
            Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(path)).StatusCode);
            if (path.EndsWith("/Sessions")) continue;
            var post = await WebFixture.PostFormAsync(b, path, new(), $"/Users/{userA}/Sessions/RevokeAll");
            Assert.True(post.StatusCode == HttpStatusCode.NotFound, path + " " + post.StatusCode);
        }
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{userA}/Sessions", new(), $"/Users/{userA}/Sessions/RevokeAll")).StatusCode);
        Assert.Equal([sidB], await ApiSessionsAsync(api, userB));
    }

    [Fact]
    public async Task State_is_computed_from_the_fields_and_the_clock()
    {
        using var f = new WebFixture(true, s => s.AddSingleton(new WebOptions { IdleTimeout = TimeSpan.FromDays(1000), AbsoluteTimeout = TimeSpan.FromDays(1000) }));
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var (user, name, _, appName) = await UserWithAppAsync(api, TimeSpan.FromHours(1)); // its sessions end with the account
        var (sid, _) = await StartSessionAsync(f, name, appName);
        var row = () => Regex.Match(b.GetStringAsync($"/Users/{user}/Sessions").GetAwaiter().GetResult(), "<tr>.*?</tr>", RegexOptions.Singleline | RegexOptions.RightToLeft).Value;
        Assert.Contains("active", row());
        Assert.Contains($"Revoke/{sid}", row());
        f.Time.Advance(TimeSpan.FromHours(2));
        var expired = row();
        Assert.Contains("expired", expired);
        Assert.DoesNotContain("active", expired);
        Assert.DoesNotContain("Revoke/", expired);
        Assert.Contains("no active sessions", await b.GetStringAsync($"/Users/{user}/Sessions/RevokeAll"));
    }

    [Fact]
    public async Task A_revoked_session_the_api_still_lists_shows_as_revoked_and_text_is_encoded()
    {
        var hostile = "<script>alert(1)</script>\"'";
        var when = DateTimeOffset.UtcNow;
        var sid = Guid.NewGuid();
        var uid = Guid.Empty;
        var appId = Guid.NewGuid();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method == HttpMethod.Get && path.EndsWith($"/users/{uid}/sessions"))
                return Json(new { items = new[] { new { id = sid, userId = uid, appId, createdAt = when, lastUsedAt = when, expiresAt = when.AddDays(1), revokedAt = when } }, nextCursor = "a b&c=<x>" });
            if (r.Method == HttpMethod.Get && path.EndsWith($"/applications/{appId}"))
                return Json(new { id = appId, name = hostile });
            return null;
        })));
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        uid = (await UserWithAppAsync(api)).User;
        var html = await b.GetStringAsync($"/Users/{uid}/Sessions");
        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("revoked", html);
        Assert.DoesNotContain("/Revoke/", html); // nothing to revoke
        Assert.Contains($"Sessions?cursor={Uri.EscapeDataString("a b&c=<x>")}\">Next page", html);
    }

    private static HttpResponseMessage Json(object o) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(o), System.Text.Encoding.UTF8, "application/json") };

    [Fact]
    public async Task A_bad_cursor_starts_over_at_the_first_page()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, _, _, _) = await UserWithAppAsync(api);
        var r = await b.GetAsync($"/Users/{user}/Sessions?cursor=garbage");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal($"/Users/{user}/Sessions", r.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Revoking_the_own_ui_session_ends_it_cleanly()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var me = await AdminIdAsync(api);
        var list = await b.GetStringAsync($"/Users/{me}/Sessions");
        Assert.Contains("(your current session)", list);
        var ownRow = Regex.Matches(list, "<tr>.*?</tr>", RegexOptions.Singleline).Single(m => m.Value.Contains("your current session")).Value;
        var own = Guid.Parse(Regex.Match(ownRow, "Revoke/([0-9a-f-]{36})").Groups[1].Value);
        Assert.Contains("Revoking it signs you out", await b.GetStringAsync($"/Users/{me}/Sessions/Revoke/{own}"));

        var r = await WebFixture.PostFormAsync(b, $"/Users/{me}/Sessions/Revoke/{own}", new());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        var after = await b.GetAsync("/Users");
        Assert.Equal(HttpStatusCode.Redirect, after.StatusCode);
        Assert.Equal("/Login", after.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Login?ended=1")).StatusCode);
    }

    [Fact]
    public async Task Revoke_all_on_oneself_ends_the_ui_session_cleanly()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var me = await AdminIdAsync(api);
        var other = await _f.SignedInAsync(); // a second browser session of the same admin
        Assert.Contains("signs you out at once", await b.GetStringAsync($"/Users/{me}/Sessions/RevokeAll"));
        var r = await WebFixture.PostFormAsync(b, $"/Users/{me}/Sessions/RevokeAll", new());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.Equal("/Login", (await b.GetAsync("/Users")).Headers.Location?.OriginalString);
        // the other browser's API session was revoked as well: its next call ends it, again without an error page
        var next = await other.GetAsync("/Users");
        Assert.Equal(HttpStatusCode.SeeOther, next.StatusCode);
        Assert.StartsWith("/Login", next.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Revoking_another_session_of_oneself_or_a_session_of_another_user_keeps_the_ui_session()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var me = await AdminIdAsync(api);
        var second = await _f.SignedInAsync();
        var list = await b.GetStringAsync($"/Users/{me}/Sessions");
        var foreign = Regex.Matches(list, "<tr>.*?</tr>", RegexOptions.Singleline).First(m => !m.Value.Contains("your current session") && m.Value.Contains("Revoke/")).Value;
        var otherId = Guid.Parse(Regex.Match(foreign, "Revoke/([0-9a-f-]{36})").Groups[1].Value);
        Assert.DoesNotContain("signs you out", await b.GetStringAsync($"/Users/{me}/Sessions/Revoke/{otherId}"));
        var r = await WebFixture.PostFormAsync(b, $"/Users/{me}/Sessions/Revoke/{otherId}", new());
        Assert.Equal($"/Users/{me}/Sessions?done=revoked", r.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);

        var (user, name, _, appName) = await UserWithAppAsync(api);
        var (sid, _) = await StartSessionAsync(_f, name, appName);
        var r2 = await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/Revoke/{sid}", new());
        Assert.Equal($"/Users/{user}/Sessions?done=revoked", r2.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
        Assert.Empty(await ApiSessionsAsync(api, user));
        _ = second;
    }

    [Fact]
    public async Task Refusals_show_the_api_status_with_fixed_texts_and_the_detail_is_only_logged()
    {
        var log = new CaptureLog();
        HttpStatusCode? armed = null;
        WebFixture? f = null;
        f = new WebFixture(false, s =>
        {
            s.AddSingleton<ILoggerProvider>(log);
            s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
                armed is { } code && r.Method == HttpMethod.Delete && r.RequestUri!.AbsolutePath.Contains("ssions")
                    ? new HttpResponseMessage(code) { Content = new StringContent("{\"detail\":\"internal-wording\\u0007xyz\"}", System.Text.Encoding.UTF8, "application/json") }
                    : null));
        });
        using var fixture = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var (user, name, _, appName) = await UserWithAppAsync(api);
        var (sid, _) = await StartSessionAsync(f, name, appName);

        armed = HttpStatusCode.Conflict;
        foreach (var path in new[] { $"/Users/{user}/Sessions/Revoke/{sid}", $"/Users/{user}/Sessions/RevokeAll" })
        {
            var resp = await WebFixture.PostFormAsync(b, path, new());
            Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
            var body = await resp.Content.ReadAsStringAsync();
            Assert.DoesNotContain("internal-wording", body);
            Assert.Equal("The sessions could not be changed.", Alert(body));
        }
        Assert.Contains("internal-wordingxyz", string.Join('\n', log.Lines));
        Assert.DoesNotContain('\u0007', string.Join('\n', log.Lines));

        armed = HttpStatusCode.NotFound;
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/Revoke/{sid}", new())).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/RevokeAll", new())).StatusCode);

        armed = HttpStatusCode.ServiceUnavailable;
        foreach (var path in new[] { $"/Users/{user}/Sessions/Revoke/{sid}", $"/Users/{user}/Sessions/RevokeAll" })
        {
            var resp = await WebFixture.PostFormAsync(b, path, new());
            Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
            var body = await resp.Content.ReadAsStringAsync();
            Assert.DoesNotContain("internal-wording", body);
        }
        armed = null;
        Assert.Equal([sid], await ApiSessionsAsync(api, user));
    }

    [Fact]
    public async Task Revoking_is_audited_under_the_signed_in_admin()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (user, name, _, appName) = await UserWithAppAsync(api);
        var (sid, _) = await StartSessionAsync(_f, name, appName);
        await StartSessionAsync(_f, name, appName);
        await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/Revoke/{sid}", new());
        await WebFixture.PostFormAsync(b, $"/Users/{user}/Sessions/RevokeAll", new());
        var me = (await AdminIdAsync(api)).ToString();
        foreach (var (action, key) in new[] { ("DELETE /v1/users/{id}/sessions/{sessionId}", sid.ToString()), ("DELETE /v1/users/{id}/sessions", user.ToString()) })
        {
            var rows = JsonDocument.Parse(await api.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString(action) + "&limit=200")).RootElement.GetProperty("items").EnumerateArray()
                .Where(e => (e.GetProperty("target").GetString() ?? "").Contains(key)).ToList();
            Assert.Equal(me, Assert.Single(rows).GetProperty("actor").GetString());
        }
    }
}
