extern alias api;

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Web.Tests;

public class Users5eTests : IClassFixture<WebFixture>
{
    private const string Password = "a long enough password";
    private readonly WebFixture _f;

    public Users5eTests(WebFixture f) => _f = f;

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

    private static async Task<HttpClient> ApiAdminAsync(WebFixture f, string user = WebFixture.AdminName, string password = WebFixture.AdminPassword)
    {
        var c = f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = user, password, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private Task<HttpClient> ApiAdminAsync() => ApiAdminAsync(_f);

    private static async Task<Guid> CreateUserAsync(HttpClient api, string username, string kind = "person")
    {
        var r = await api.PostAsJsonAsync("/v1/users", new { username, email = username + "@example.com", displayName = "", kind });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<Guid> CreateAppAsync(HttpClient api, string name)
    {
        var r = await api.PostAsJsonAsync("/v1/applications", new { name });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<Guid> CreateRoleAsync(HttpClient api, Guid app, string name)
    {
        var r = await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name, description = "d" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<(Guid App, Guid Role)> GatekeeperAdminRoleAsync(HttpClient api)
    {
        var apps = await api.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        return (gk, roles.GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid());
    }

    private static async Task<List<Guid>> UserRolesAsync(HttpClient api, Guid user) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/roles?limit=200")).GetProperty("items").EnumerateArray().Select(r => r.GetProperty("id").GetGuid()).ToList();

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static void ForgetAdminCache(WebFixture f) => ((MemoryCache)f.Api.Services.GetRequiredService<IMemoryCache>()).Clear();

    private async Task<(HttpClient Browser, Guid Id, string Name)> SecondAdminAsync(WebFixture? f = null)
    {
        f ??= _f;
        var api = await ApiAdminAsync(f);
        var name = Unique("adm");
        var id = await CreateUserAsync(api, name);
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var (_, adminRole) = await GatekeeperAdminRoleAsync(api);
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null)).StatusCode);
        var b = f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
        return (b, id, name);
    }

    [Fact]
    public async Task Pages_need_a_session_and_posts_need_the_antiforgery_token()
    {
        var anon = _f.Browser();
        var uid = Guid.NewGuid();
        foreach (var path in new[] { $"/Users/{uid}/Roles", $"/Users/{uid}/Roles/Add", $"/Users/{uid}/Roles/Remove/{Guid.NewGuid()}", $"/Users/{uid}/Password" })
        {
            var resp = await anon.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.Equal("/Login", resp.Headers.Location?.OriginalString);
        }

        var api = await ApiAdminAsync();
        var s = await _f.SignedInAsync();
        var id = await CreateUserAsync(api, Unique("csrf"));
        var app = await CreateAppAsync(api, Unique("csrfapp"));
        var role = await CreateRoleAsync(api, app, "reader");
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{role}", null)).StatusCode);
        var other = await CreateRoleAsync(api, app, "writer");

        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/{id}/Roles/Add", new FormUrlEncodedContent(new Dictionary<string, string> { ["app"] = app.ToString(), ["RoleId"] = other.ToString() }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/{id}/Roles/Remove/{role}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/{id}/Password", new FormUrlEncodedContent(new Dictionary<string, string> { ["Password"] = Password, ["Confirm"] = Password }))).StatusCode);
        Assert.Equal([role], await UserRolesAsync(api, id));
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.PostAsJsonAsync("/v1/auth/login", new { username = "x", password = Password, application = "gatekeeper" })).StatusCode);
    }

    [Fact]
    public async Task A_role_can_be_added_in_two_steps_listed_and_removed_with_confirmation()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var name = Unique("rt");
        var id = await CreateUserAsync(api, name);
        var appName = Unique("shop");
        var app = await CreateAppAsync(api, appName);
        var role = await CreateRoleAsync(api, app, "reader");
        await CreateRoleAsync(api, app, "writer");

        Assert.Contains("No roles.", await b.GetStringAsync($"/Users/{id}/Roles"));
        // step 1: applications; step 2: roles of the chosen one
        var step1 = await b.GetStringAsync($"/Users/{id}/Roles/Add");
        Assert.Contains($"<option value=\"{app}\">{appName}</option>", step1);
        Assert.DoesNotContain("name=\"RoleId\"", step1);
        var step2 = await b.GetStringAsync($"/Users/{id}/Roles/Add?app={app}");
        Assert.Contains($"<option value=\"{role}\">reader</option>", step2);
        Assert.Contains("writer", step2);

        var added = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = role.ToString() }, $"/Users/{id}/Roles/Add?app={app}");
        Assert.Equal(HttpStatusCode.Redirect, added.StatusCode);
        Assert.Equal($"/Users/{id}/Roles?done=added", added.Headers.Location?.OriginalString);
        Assert.Equal([role], await UserRolesAsync(api, id));
        var list = await b.GetStringAsync($"/Users/{id}/Roles?done=added");
        Assert.Contains("Role added.", list);
        Assert.Contains("<td>reader</td>", list);
        Assert.Contains($"<td>{appName}</td>", list);
        Assert.Contains($"/Users/{id}/Roles/Remove/{role}", list);

        // confirmation first: a GET changes nothing
        var confirm = await b.GetStringAsync($"/Users/{id}/Roles/Remove/{role}");
        Assert.Contains($"<strong>{appName}</strong>", confirm);
        Assert.Equal([role], await UserRolesAsync(api, id));
        var removed = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{role}", new());
        Assert.Equal($"/Users/{id}/Roles?done=removed", removed.Headers.Location?.OriginalString);
        Assert.Empty(await UserRolesAsync(api, id));
        Assert.Contains("No roles.", await b.GetStringAsync($"/Users/{id}/Roles"));
        // removing it again: the user no longer holds it
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{id}/Roles/Remove/{role}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{role}", new(), $"/Users/{id}/Roles")).StatusCode);
    }

    [Fact]
    public async Task Role_and_user_ids_are_checked_against_the_route()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var id = await CreateUserAsync(api, Unique("idor"));
        var bystander = await CreateUserAsync(api, Unique("byst"));
        var appA = await CreateAppAsync(api, Unique("appa"));
        var appB = await CreateAppAsync(api, Unique("appb"));
        var roleA = await CreateRoleAsync(api, appA, "a-role");
        var roleB = await CreateRoleAsync(api, appB, "b-role");
        await api.PutAsync($"/v1/users/{bystander}/roles/{roleB}", null);

        // a role of app B submitted with app A
        var crafted = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", new() { ["app"] = appA.ToString(), ["RoleId"] = roleB.ToString() }, $"/Users/{id}/Roles/Add?app={appA}");
        Assert.Equal(HttpStatusCode.NotFound, crafted.StatusCode);
        Assert.Empty(await UserRolesAsync(api, id));
        // unknown role / unknown app / missing role / garbage ids
        foreach (var fields in new[]
        {
            new Dictionary<string, string> { ["app"] = appA.ToString(), ["RoleId"] = Guid.NewGuid().ToString() },
            new Dictionary<string, string> { ["app"] = Guid.NewGuid().ToString(), ["RoleId"] = roleA.ToString() },
            new Dictionary<string, string> { ["RoleId"] = roleA.ToString() },
        })
            Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", fields, $"/Users/{id}/Roles")).StatusCode);
        var missing = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", new() { ["app"] = appA.ToString() }, $"/Users/{id}/Roles");
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode); // no role chosen is never "all roles" or "remove"
        var garbage = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", new() { ["app"] = appA.ToString(), ["RoleId"] = "not-a-guid" }, $"/Users/{id}/Roles");
        Assert.Equal(HttpStatusCode.BadRequest, garbage.StatusCode);
        Assert.Empty(await UserRolesAsync(api, id));
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{id}/Roles/Add?app={Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{Guid.NewGuid()}/Roles")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{Guid.NewGuid()}/Roles/Add")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{Guid.NewGuid()}/Password")).StatusCode);

        // a role the bystander holds cannot be removed through this user's URL
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{id}/Roles/Remove/{roleB}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{roleB}", new(), $"/Users/{id}/Roles")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{Guid.NewGuid()}", new(), $"/Users/{id}/Roles")).StatusCode);
        Assert.Equal([roleB], await UserRolesAsync(api, bystander));
        // the bystander's own page works
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync($"/Users/{bystander}/Roles/Remove/{roleB}")).StatusCode);
    }

    [Fact]
    public async Task The_reserved_application_offers_only_the_admin_role_and_a_non_person_cannot_get_it()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var (gk, adminRole) = await GatekeeperAdminRoleAsync(api);
        var shared = await CreateUserAsync(api, Unique("shared"), "shared");

        var step2 = await b.GetStringAsync($"/Users/{shared}/Roles/Add?app={gk}");
        Assert.Contains($"<option value=\"{adminRole}\">admin</option>", step2);
        Assert.Single(Regex.Matches(step2, "<option value="));
        Assert.Contains("reserved", step2);

        var r = await WebFixture.PostFormAsync(b, $"/Users/{shared}/Roles/Add", new() { ["app"] = gk.ToString(), ["RoleId"] = adminRole.ToString() }, $"/Users/{shared}/Roles/Add?app={gk}");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Contains("Only a person can hold the admin role.", Alert(html));
        Assert.Contains("name=\"RoleId\"", html); // the form is still there
        Assert.Empty(await UserRolesAsync(api, shared));

        // a person can get it, and is then listed with it
        var person = await CreateUserAsync(api, Unique("person"));
        var ok = await WebFixture.PostFormAsync(b, $"/Users/{person}/Roles/Add", new() { ["app"] = gk.ToString(), ["RoleId"] = adminRole.ToString() }, $"/Users/{person}/Roles/Add?app={gk}");
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Contains("<td>gatekeeper</td>", await b.GetStringAsync($"/Users/{person}/Roles"));
        await b.GetAsync($"/Users/{person}/Roles"); // remove again so the shared fixture keeps few admins
        await WebFixture.PostFormAsync(b, $"/Users/{person}/Roles/Remove/{adminRole}", new());
    }

    [Fact]
    public async Task Removing_the_last_admin_role_shows_the_409_and_keeps_the_session()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var (_, adminRole) = await GatekeeperAdminRoleAsync(api);
        var me = (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetGuid();

        var page = await b.GetStringAsync($"/Users/{me}/Roles/Remove/{adminRole}");
        Assert.Contains("your own admin role", page);
        var r = await WebFixture.PostFormAsync(b, $"/Users/{me}/Roles/Remove/{adminRole}", new());
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("without an active administrator", Alert(await r.Content.ReadAsStringAsync()));
        Assert.Contains(adminRole, await UserRolesAsync(api, me));
        ForgetAdminCache(f);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode); // still signed in
    }

    [Fact]
    public async Task An_administrator_who_removes_their_own_admin_role_lands_on_the_sign_in_page()
    {
        var (b, id, _) = await SecondAdminAsync();
        var (_, adminRole) = await GatekeeperAdminRoleAsync(await ApiAdminAsync());
        var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{adminRole}", new());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.DoesNotContain(adminRole, await UserRolesAsync(await ApiAdminAsync(), id));
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Login?ended=1")).StatusCode);
        Assert.Equal("/Login", (await b.GetAsync($"/Users/{id}/Roles")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Removing_someone_elses_admin_role_keeps_the_own_session()
    {
        var (b, _, _) = await SecondAdminAsync();
        var (other, otherId, _) = await SecondAdminAsync();
        var (_, adminRole) = await GatekeeperAdminRoleAsync(await ApiAdminAsync());
        var r = await WebFixture.PostFormAsync(b, $"/Users/{otherId}/Roles/Remove/{adminRole}", new());
        Assert.Equal($"/Users/{otherId}/Roles?done=removed", r.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
        ForgetAdminCache(_f);
        Assert.Equal("/Login?ended=1", (await other.GetAsync("/Users")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Password_round_trip_never_echoes_logs_or_audits_the_password()
    {
        var log = new CaptureLog();
        using var f = new WebFixture(false, s => s.AddSingleton<ILoggerProvider>(log));
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var name = Unique("pw");
        var id = await CreateUserAsync(api, name);
        var secret = "S3cret-" + Guid.NewGuid().ToString("N");

        var form = await b.GetStringAsync($"/Users/{id}/Password");
        Assert.Equal(2, Regex.Matches(form, "autocomplete=\"new-password\"").Count);
        Assert.Contains("type=\"password\"", form);
        foreach (var field in new[] { "Password", "Confirm" })
            Assert.DoesNotContain("value=", Regex.Match(form, $"<input name=\"{field}\"[^>]*>").Value);

        // mismatch, empty and too short: refused, nothing echoed, password not set
        foreach (var (pw, confirm, status, text) in new[]
        {
            (secret, secret + "x", HttpStatusCode.BadRequest, "not the same"),
            ("", "", HttpStatusCode.BadRequest, "Enter a password"),
            ("short" + secret[..2], "short" + secret[..2], HttpStatusCode.BadRequest, "12 to 128"),
        })
        {
            var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = pw, ["Confirm"] = confirm }, $"/Users/{id}/Password");
            Assert.Equal(status, r.StatusCode);
            var body = await r.Content.ReadAsStringAsync();
            Assert.Contains(text, Alert(body));
            if (pw.Length > 0) Assert.DoesNotContain(pw, body);
            Assert.DoesNotContain(secret, body);
            Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
        }
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.PostAsJsonAsync("/v1/auth/login", new { username = name, password = secret, application = "x" })).StatusCode);

        // a missing confirm field is a mismatch, never "set it anyway"
        var noConfirm = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = secret }, $"/Users/{id}/Password");
        Assert.Equal(HttpStatusCode.BadRequest, noConfirm.StatusCode);

        var ok = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = secret, ["Confirm"] = secret }, $"/Users/{id}/Password");
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Equal($"/Users/{id}/Password?done=set", ok.Headers.Location?.OriginalString);
        Assert.DoesNotContain(secret, string.Join(' ', ok.Headers.SelectMany(h => h.Value)));
        var done = await b.GetStringAsync(ok.Headers.Location!.OriginalString);
        Assert.Contains("Password set.", done);
        Assert.DoesNotContain(secret, done);

        // the password works for the user: needs a role to log in, so check through the API's own login of the gatekeeper app
        var (_, adminRole) = await GatekeeperAdminRoleAsync(api);
        await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null);
        Assert.Equal(HttpStatusCode.OK, (await api.PostAsJsonAsync("/v1/auth/login", new { username = name, password = secret, application = "gatekeeper" })).StatusCode);
        await api.DeleteAsync($"/v1/users/{id}/roles/{adminRole}");

        var audit = await api.GetStringAsync("/v1/audit?limit=200");
        Assert.DoesNotContain(secret, audit);
        var me = (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetString();
        var row = JsonDocument.Parse(await api.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("PUT /v1/users/{id}/password") + "&limit=5")).RootElement.GetProperty("items")[0];
        Assert.Equal(me, row.GetProperty("actor").GetString());
        Assert.DoesNotContain(secret, string.Join('\n', log.Lines));
    }

    [Fact]
    public async Task Password_is_not_leaked_when_the_api_fails()
    {
        var log = new CaptureLog();
        var mode = "";
        WebFixture? f = null;
        f = new WebFixture(false, s =>
        {
            s.AddSingleton<ILoggerProvider>(log);
            s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            {
                if (mode == "" || r.Method != HttpMethod.Put || !r.RequestUri!.AbsolutePath.EndsWith("/password")) return null;
                return mode switch
                {
                    "503" => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                    "down" => throw new HttpRequestException("refused"),
                    "400" => new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"detail\":\"echo-" + "SECRET-PW\"}", System.Text.Encoding.UTF8, "application/json") },
                    "401" => new HttpResponseMessage(HttpStatusCode.Unauthorized),
                    _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("SECRET-PW boom") },
                };
            }));
        });
        using var _ = f;
        var b = await f.SignedInAsync();
        var id = await CreateUserAsync(await ApiAdminAsync(f), Unique("pwf"));
        var pw = "Pa55-SECRET-PW-xx";
        foreach (var (m, status) in new[] { ("503", HttpStatusCode.ServiceUnavailable), ("down", HttpStatusCode.ServiceUnavailable), ("500", HttpStatusCode.BadGateway), ("400", HttpStatusCode.BadRequest) })
        {
            mode = m;
            var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = pw, ["Confirm"] = pw }, $"/Users/{id}/Password");
            Assert.Equal(status, r.StatusCode);
            var body = await r.Content.ReadAsStringAsync();
            Assert.DoesNotContain("SECRET-PW", body); // neither the password nor the API's wording
        }
        Assert.DoesNotContain("SECRET-PW", string.Join('\n', log.Lines).Replace("echo-SECRET-PW", ""));
        // a 401 for the PUT ends the web session cleanly
        mode = "401";
        var gone = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = pw, ["Confirm"] = pw }, $"/Users/{id}/Password");
        Assert.Equal(HttpStatusCode.SeeOther, gone.StatusCode);
        Assert.Equal("/Login?ended=1", gone.Headers.Location?.OriginalString);
        Assert.Equal("/Login", (await b.GetAsync("/Users")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task An_administrator_who_changes_their_own_password_lands_on_the_sign_in_page()
    {
        var (b, id, name) = await SecondAdminAsync();
        Assert.Contains("your own account", await b.GetStringAsync($"/Users/{id}/Password"));
        var fresh = "a brand new password";
        var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = fresh, ["Confirm"] = fresh });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.Equal("/Login", (await b.GetAsync("/Users")).Headers.Location?.OriginalString);
        var again = _f.Browser();
        Assert.Equal(HttpStatusCode.OK, (await WebFixture.PostFormAsync(again, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode); // old password refused: login page again
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(again, "/Login", new() { ["Username"] = name, ["Password"] = fresh })).StatusCode);
    }

    [Fact]
    public async Task A_session_the_api_ended_meanwhile_gets_the_sign_in_page_on_the_role_pages()
    {
        var (b, id, _) = await SecondAdminAsync();
        // someone else sets this administrator's password: their refresh session is revoked, the access token is renewed on demand
        Assert.Equal(HttpStatusCode.NoContent, (await (await ApiAdminAsync()).PutAsJsonAsync($"/v1/users/{id}/password", new { password = "another long password" })).StatusCode);
        ForgetAdminCache(_f);
        var r = await b.GetAsync($"/Users/{id}/Roles");
        Assert.True(r.StatusCode is HttpStatusCode.OK or HttpStatusCode.SeeOther, r.StatusCode.ToString());
        if (r.StatusCode == HttpStatusCode.SeeOther) Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
    }

    [Theory]
    [InlineData("503", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("500", HttpStatusCode.BadGateway, "could not complete")]
    [InlineData("404", HttpStatusCode.NotFound, "")]
    public async Task Api_failures_on_the_role_pages_get_an_honest_status_without_leaking_detail(string mode, HttpStatusCode expected, string text)
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (!armed || !r.RequestUri!.AbsolutePath.Contains("/roles")) return null;
            return mode switch
            {
                "503" => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                "404" => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") },
                _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{\"detail\":\"secret-internal\"}") },
            };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var id = await CreateUserAsync(api, Unique("fail"));
        var app = await CreateAppAsync(api, Unique("failapp"));
        var role = await CreateRoleAsync(api, app, "r");
        armed = true;
        var responses = new List<HttpResponseMessage>
        {
            await b.GetAsync($"/Users/{id}/Roles"),
            await b.GetAsync($"/Users/{id}/Roles/Add?app={app}"),
            await b.GetAsync($"/Users/{id}/Roles/Remove/{role}"),
            await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = role.ToString() }, $"/Users/{id}/Password"),
        };
        foreach (var r in responses)
        {
            var body = await r.Content.ReadAsStringAsync();
            Assert.Equal(expected, r.StatusCode);
            Assert.Contains(text, body);
            Assert.DoesNotContain("secret-internal", body);
        }
    }

    [Fact]
    public async Task Hostile_text_is_encoded_and_unknown_query_values_are_ignored()
    {
        var hostile = "<script>alert(1)</script><img src=x onerror=1>\"'";
        var userId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (path == $"/v1/users/{userId}") return Json($"{{\"id\":\"{userId}\",\"username\":{JsonSerializer.Serialize(hostile)},\"email\":\"e@example.com\",\"displayName\":\"\",\"isActive\":true,\"kind\":\"person\",\"expiresAt\":null}}");
            if (path == $"/v1/users/{userId}/roles") return Json($"{{\"items\":[{{\"id\":\"{roleId}\",\"appId\":\"{appId}\",\"name\":{JsonSerializer.Serialize(hostile)},\"description\":\"\"}}],\"nextCursor\":{JsonSerializer.Serialize(hostile)}}}");
            if (path == $"/v1/roles/{roleId}") return Json($"{{\"id\":\"{roleId}\",\"appId\":\"{appId}\",\"name\":{JsonSerializer.Serialize(hostile)},\"description\":\"\"}}");
            if (path == $"/v1/applications/{appId}") return Json($"{{\"id\":\"{appId}\",\"name\":{JsonSerializer.Serialize(hostile)}}}");
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var list = await b.GetStringAsync($"/Users/{userId}/Roles?done=" + Uri.EscapeDataString(hostile));
        Assert.DoesNotContain("<script>alert", list);
        Assert.DoesNotContain("<img src=x", list);
        Assert.Contains("&lt;script&gt;", list);
        Assert.DoesNotContain("class=\"notice\"", list);
        var cursorLink = Regex.Match(list, "href=\"(/Users/[^\"]*cursor=[^\"]*)\"").Groups[1].Value;
        Assert.DoesNotContain("<", cursorLink);
        var add = await b.GetAsync($"/Users/{userId}/Roles/Add?app=" + Uri.EscapeDataString(hostile));
        Assert.DoesNotContain("<script>alert", await add.Content.ReadAsStringAsync());
        var remove = await b.GetStringAsync($"/Users/{userId}/Roles/Remove/{roleId}");
        Assert.DoesNotContain("<script>alert", remove);
        Assert.Contains("&lt;script&gt;", remove);
        Assert.DoesNotContain("<script>alert", await b.GetStringAsync($"/Users/{userId}/Password"));

        static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
    }

    [Fact]
    public async Task Long_role_lists_page_with_the_cursor_and_app_names_use_few_calls()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var id = await CreateUserAsync(api, Unique("many"));
        var app = await CreateAppAsync(api, Unique("many"));
        var names = new List<string>();
        for (var i = 0; i < 27; i++)
        {
            var n = $"role-{i:00}";
            names.Add(n);
            await api.PutAsync($"/v1/users/{id}/roles/{await CreateRoleAsync(api, app, n)}", null);
        }
        var first = await b.GetStringAsync($"/Users/{id}/Roles");
        Assert.Equal(25, Regex.Matches(first, "/Roles/Remove/").Count);
        var next = WebUtility.HtmlDecode(Regex.Match(first, "href=\"(/Users/[^\"]*cursor=[^\"]*)\">Next page").Groups[1].Value);
        Assert.NotEmpty(next);
        var second = await b.GetStringAsync(next);
        Assert.Equal(2, Regex.Matches(second, "/Roles/Remove/").Count);
        Assert.DoesNotContain("Next page", second);
        // an edited cursor goes back to the first page
        var bad = await b.GetAsync($"/Users/{id}/Roles?cursor=garbage");
        Assert.Equal(HttpStatusCode.Redirect, bad.StatusCode);
        Assert.Equal($"/Users/{id}/Roles", bad.Headers.Location?.OriginalString);
        // the add form lists the application with its roles on one page and survives a bad cursor
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync($"/Users/{id}/Roles/Add?app={app}&cursor=garbage")).StatusCode);
    }

    [Fact]
    public async Task Role_and_password_changes_are_audited_under_the_signed_in_admin()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var id = await CreateUserAsync(api, Unique("aud"));
        var app = await CreateAppAsync(api, Unique("audapp"));
        var role = await CreateRoleAsync(api, app, "r");
        await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = role.ToString() }, $"/Users/{id}/Password");
        await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{role}", new());
        var me = (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetString();
        foreach (var action in new[] { "PUT /v1/users/{id}/roles/{roleId}", "DELETE /v1/users/{id}/roles/{roleId}" })
        {
            var audit = JsonDocument.Parse(await api.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString(action) + "&limit=200")).RootElement.GetProperty("items").EnumerateArray()
                .Where(e => (e.GetProperty("target").GetString() ?? "").Contains(id.ToString())).ToList();
            Assert.Equal(me, Assert.Single(audit).GetProperty("actor").GetString());
        }
    }

    [Fact]
    public async Task Role_refusals_show_fixed_texts_and_the_api_wording_is_logged_not_shown()
    {
        var log = new CaptureLog();
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s =>
        {
            s.AddSingleton<ILoggerProvider>(log);
            s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
                armed && r.RequestUri!.AbsolutePath.Contains("/roles/") && r.Method != HttpMethod.Get
                    ? new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("{\"detail\":\"internal-wording\\u0007xyz\"}", System.Text.Encoding.UTF8, "application/json") }
                    : null));
        });
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var user = await CreateUserAsync(api, Unique("ref"));
        var app = await CreateAppAsync(api, Unique("refapp"));
        var role = await CreateRoleAsync(api, app, "r");
        await api.PutAsync($"/v1/users/{user}/roles/{role}", null);
        armed = true;
        var add = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = role.ToString() }, $"/Users/{user}/Roles/Add?app={app}");
        Assert.Equal(HttpStatusCode.Conflict, add.StatusCode);
        var addBody = await add.Content.ReadAsStringAsync();
        Assert.DoesNotContain("internal-wording", addBody);
        Assert.Equal("The role could not be changed because of a conflict.", Alert(addBody));
        var rem = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Remove/{role}", new());
        Assert.Equal(HttpStatusCode.Conflict, rem.StatusCode);
        var remBody = await rem.Content.ReadAsStringAsync();
        Assert.DoesNotContain("internal-wording", remBody);
        Assert.Equal("The role could not be changed because of a conflict.", Alert(remBody));
        var lines = string.Join('\n', log.Lines);
        Assert.Contains("internal-wordingxyz", lines);
        Assert.DoesNotContain('\u0007', lines);
    }

    [Fact]
    public async Task Last_admin_removal_shows_the_fixed_text()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var (_, adminRole) = await GatekeeperAdminRoleAsync(api);
        var me = (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetGuid();
        var r = await WebFixture.PostFormAsync(b, $"/Users/{me}/Roles/Remove/{adminRole}", new());
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal("This would leave Gatekeeper without an active administrator.", Alert(await r.Content.ReadAsStringAsync()));
    }

    [Fact]
    public async Task Add_ignores_role_and_app_in_the_query_string_on_post()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var user = await CreateUserAsync(api, Unique("qs"));
        var app = await CreateAppAsync(api, Unique("qsapp"));
        var role = await CreateRoleAsync(api, app, "r");
        var noRole = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add?RoleId={role}", new() { ["app"] = app.ToString() }, $"/Users/{user}/Roles/Add?app={app}");
        Assert.Equal(HttpStatusCode.BadRequest, noRole.StatusCode);
        var noApp = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add?app={app}&RoleId={role}", new(), $"/Users/{user}/Roles/Add?app={app}");
        Assert.Equal(HttpStatusCode.NotFound, noApp.StatusCode);
        Assert.Empty(await UserRolesAsync(api, user));
    }

    [Fact]
    public async Task A_non_person_gets_a_hint_on_the_reserved_application_and_a_person_does_not()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var (gk, _) = await GatekeeperAdminRoleAsync(api);
        var shared = await CreateUserAsync(api, Unique("hs"), "shared");
        var person = await CreateUserAsync(api, Unique("hp"));
        Assert.Contains("only a person can hold the admin role", await b.GetStringAsync($"/Users/{shared}/Roles/Add?app={gk}"));
        Assert.DoesNotContain("is not a person", await b.GetStringAsync($"/Users/{person}/Roles/Add?app={gk}"));
    }

    [Fact]
    public async Task The_ownership_check_on_remove_stops_after_a_page_limit()
    {
        var calls = 0;
        WebFixture? f = null;
        Guid user = Guid.Empty;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (user == Guid.Empty || r.RequestUri!.AbsolutePath != $"/v1/users/{user}/roles") return null;
            Interlocked.Increment(ref calls);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"items\":[],\"nextCursor\":\"more\"}", System.Text.Encoding.UTF8, "application/json") };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        user = await CreateUserAsync(api, Unique("pg"));
        var app = await CreateAppAsync(api, Unique("pgapp"));
        var role = await CreateRoleAsync(api, app, "r");
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{user}/Roles/Remove/{role}")).StatusCode);
        Assert.Equal(50, calls);
    }

    [Fact]
    public async Task A_failing_or_cancelled_api_logout_still_ends_the_local_session()
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed && r.RequestUri!.AbsolutePath == "/v1/auth/logout" ? throw new OperationCanceledException() : null)));
        using var _ = f;
        var api = await ApiAdminAsync(f);
        var name = Unique("lg");
        var id = await CreateUserAsync(api, name);
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var (_, adminRole) = await GatekeeperAdminRoleAsync(api);
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null)).StatusCode);
        var b = f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
        armed = true;
        var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{adminRole}", new());
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.Equal("/Login", (await b.GetAsync("/Users")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task The_password_page_explains_that_issued_access_tokens_stay_valid()
    {
        var b = await _f.SignedInAsync();
        var id = await CreateUserAsync(await ApiAdminAsync(), Unique("txt"));
        var html = await b.GetStringAsync($"/Users/{id}/Password");
        Assert.Contains("sign-in (refresh) sessions", html);
        Assert.Contains("up to 15 minutes", html);
        Assert.DoesNotContain("ends all of the user", html);
    }
}
