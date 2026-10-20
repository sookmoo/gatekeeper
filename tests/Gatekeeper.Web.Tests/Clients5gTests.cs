extern alias api;

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Web.Tests;

public partial class Clients5gTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Clients5gTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    [GeneratedRegex("gks_[A-Za-z0-9_-]{43}")]
    private static partial Regex SecretShape();

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

    private static async Task<Guid> CreateAppAsync(HttpClient api, string name)
    {
        var r = await api.PostAsJsonAsync("/v1/applications", new { name });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<(Guid Id, string Secret)> CreateClientAsync(HttpClient api, string name, Guid app, bool active = true)
    {
        var r = await api.PostAsJsonAsync("/v1/clients", new { name, application = app, isActive = active });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        var j = await r.Content.ReadFromJsonAsync<JsonElement>();
        return (j.GetProperty("id").GetGuid(), j.GetProperty("secret").GetString()!);
    }

    private static async Task<JsonElement> ApiClientAsync(HttpClient api, Guid id) => await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{id}");

    private static async Task<List<JsonElement>> ApiClientsAsync(HttpClient api, Guid? app = null) =>
        (await api.GetFromJsonAsync<JsonElement>("/v1/clients?limit=200" + (app is { } a ? $"&application={a}" : ""))).GetProperty("items").EnumerateArray().ToList();

    private static async Task<HttpStatusCode> ClientTokenAsync(WebFixture f, string name, string secret) =>
        (await f.Api.CreateClient().PostAsJsonAsync("/v1/auth/client-token", new { clientId = name, clientSecret = secret })).StatusCode;

    private static async Task GiveRoleAsync(HttpClient api, Guid app, Guid client)
    {
        var r = await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "reader", description = "d" });
        var role = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/clients/{client}/roles/{role}", null)).StatusCode);
    }

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static string HeadersOf(HttpResponseMessage r) =>
        string.Join('\n', r.Headers.Concat(r.Content.Headers).Select(h => h.Key + ": " + string.Join(',', h.Value)));

    [Fact]
    public async Task Pages_need_a_session_and_posts_need_the_antiforgery_token()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("csrf"));
        var (id, secret) = await CreateClientAsync(api, Unique("c"), app);
        var anon = _f.Browser();
        foreach (var path in new[] { "/Clients", "/Clients/Create", $"/Clients/Edit/{id}", $"/Clients/Rotate/{id}", $"/Clients/Delete/{id}" })
        {
            var resp = await anon.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.Equal("/Login", resp.Headers.Location?.OriginalString);
            Assert.Equal(HttpStatusCode.Redirect, (await anon.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        }

        var s = await _f.SignedInAsync();
        var empty = new FormUrlEncodedContent(new Dictionary<string, string>());
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync("/Clients/Create", new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = Unique("x"), ["App"] = app.ToString() }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Clients/Edit/{id}", new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = "renamed" }))).StatusCode);
        var rotate = await s.PostAsync($"/Clients/Rotate/{id}", empty);
        Assert.Equal(HttpStatusCode.BadRequest, rotate.StatusCode);
        Assert.DoesNotContain("gks_", await rotate.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Clients/Delete/{id}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Single(await ApiClientsAsync(api, app));
        await GiveRoleAsync(api, app, id);
        Assert.Equal(HttpStatusCode.OK, await ClientTokenAsync(_f, (await ApiClientAsync(api, id)).GetProperty("name").GetString()!, secret)); // the refused rotate left the secret alone
        Assert.Equal(id, (await ApiClientAsync(api, id)).GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task Create_edit_rotate_and_delete_round_trip()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var appName = Unique("shop");
        var app = await CreateAppAsync(api, appName);
        var name = Unique("svc");

        // create: the answer is the secret page itself, not a redirect
        var form = await b.GetStringAsync("/Clients/Create");
        Assert.Contains($"<option value=\"{app}\"", form);
        Assert.DoesNotContain("gks_", form);
        var created = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Null(created.Headers.Location);
        var body = await created.Content.ReadAsStringAsync();
        var secret = SecretShape().Match(body).Value;
        Assert.NotEmpty(secret);
        Assert.Single(SecretShape().Matches(body));
        Assert.Contains("no-store", created.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", created.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("autocomplete=\"off\"", body);
        Assert.Contains("shown once", body);
        Assert.Contains("href=\"/Clients\"", body);
        Assert.Contains("resubmit", body);
        Assert.DoesNotContain(secret, HeadersOf(created));
        var client = Assert.Single(await ApiClientsAsync(api, app));
        var id = client.GetProperty("id").GetGuid();
        Assert.Equal(name, client.GetProperty("name").GetString());
        Assert.True(client.GetProperty("isActive").GetBoolean());
        await GiveRoleAsync(api, app, id);
        Assert.Equal(HttpStatusCode.OK, await ClientTokenAsync(_f, name, secret));

        // list
        var list = await b.GetStringAsync("/Clients");
        Assert.Contains($"<td>{name}</td>", list);
        Assert.Contains($"<td>{appName}</td>", list);
        Assert.DoesNotContain(secret, list);

        // edit: rename and disable
        var edit = await b.GetStringAsync($"/Clients/Edit/{id}");
        Assert.DoesNotContain(secret, edit);
        Assert.Contains(appName, edit);
        var newName = Unique("renamed");
        var saved = await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = newName, ["IsActive"] = "false", ["OrigName"] = name, ["OrigIsActive"] = "true" });
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        Assert.Equal("/Clients?done=updated", saved.Headers.Location?.OriginalString);
        var after = await ApiClientAsync(api, id);
        Assert.Equal(newName, after.GetProperty("name").GetString());
        Assert.False(after.GetProperty("isActive").GetBoolean());
        Assert.Contains("Client updated.", await b.GetStringAsync("/Clients?done=updated"));
        Assert.Contains("<td>no</td>", await b.GetStringAsync($"/Clients?app={app}"));
        // enable again
        await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = newName, ["IsActive"] = "true", ["OrigName"] = newName, ["OrigIsActive"] = "false" });
        Assert.True((await ApiClientAsync(api, id)).GetProperty("isActive").GetBoolean());

        // rotate: a GET only asks; the POST answers with the new secret
        var confirm = await b.GetStringAsync($"/Clients/Rotate/{id}");
        Assert.Contains("stops working at once", confirm);
        Assert.DoesNotContain("gks_", confirm);
        Assert.Equal(HttpStatusCode.OK, await ClientTokenAsync(_f, newName, secret));
        var rotated = await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        Assert.Null(rotated.Headers.Location);
        var rotatedBody = await rotated.Content.ReadAsStringAsync();
        var newSecret = SecretShape().Match(rotatedBody).Value;
        Assert.Single(SecretShape().Matches(rotatedBody));
        Assert.NotEqual(secret, newSecret);
        Assert.Contains("no-store", rotated.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", rotated.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("autocomplete=\"off\"", rotatedBody);
        Assert.Contains("shown once", rotatedBody);
        Assert.Equal(HttpStatusCode.Unauthorized, await ClientTokenAsync(_f, newName, secret));
        Assert.Equal(HttpStatusCode.OK, await ClientTokenAsync(_f, newName, newSecret));
        // going back to the page (a plain GET) shows no secret
        Assert.DoesNotContain("gks_", await b.GetStringAsync($"/Clients/Rotate/{id}"));

        // delete: confirmation first
        var del = await b.GetStringAsync($"/Clients/Delete/{id}");
        Assert.Contains($"<strong>{newName}</strong>", del);
        Assert.Single(await ApiClientsAsync(api, app));
        var deleted = await WebFixture.PostFormAsync(b, $"/Clients/Delete/{id}", new());
        Assert.Equal("/Clients?done=deleted", deleted.Headers.Location?.OriginalString);
        Assert.Empty(await ApiClientsAsync(api, app));
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Clients/Delete/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Clients/Delete/{id}", new(), "/Clients/Create")).StatusCode);
    }

    [Fact]
    public async Task The_reserved_application_is_not_offered_and_a_crafted_post_is_refused()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var apps = (await api.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray().ToList();
        var gk = apps.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        await CreateAppAsync(api, Unique("normal"));

        var form = await b.GetStringAsync("/Clients/Create");
        Assert.DoesNotContain(gk.ToString(), form);
        Assert.DoesNotContain(">gatekeeper</option>", form);
        Assert.DoesNotContain(gk.ToString(), await b.GetStringAsync("/Clients"));

        var name = Unique("sneak");
        var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = gk.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Equal("The reserved application cannot have clients.", Alert(html));
        Assert.DoesNotContain("gks_", html);
        Assert.DoesNotContain(await ApiClientsAsync(api), c => c.GetProperty("name").GetString() == name);
    }

    [Fact]
    public async Task Unknown_ids_and_bad_input_are_refused_without_a_500()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("bad"));
        var unknown = Guid.NewGuid();
        foreach (var path in new[] { $"/Clients/Edit/{unknown}", $"/Clients/Rotate/{unknown}", $"/Clients/Delete/{unknown}" })
        {
            Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(path)).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, path, new() { ["Name"] = "x" }, "/Clients/Create")).StatusCode);
        }
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync("/Clients/Edit/not-a-guid")).StatusCode);

        // create: unknown app is a 404, no/garbage app is a 400, a bad name a 400 with the fixed text
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("a"), ["App"] = unknown.ToString() })).StatusCode);
        foreach (var appValue in new[] { "", "garbage", "{}" })
        {
            var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("a"), ["App"] = appValue }, "/Clients/Create");
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Equal("Choose an application.", Alert(await r.Content.ReadAsStringAsync()));
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("a") }, "/Clients/Create")).StatusCode);
        foreach (var bad in new[] { "", "Upper", "has space", new string('a', 65), "<b>x</b>", Guid.NewGuid().ToString() })
        {
            var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = bad, ["App"] = app.ToString() }, "/Clients/Create");
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            var html = await r.Content.ReadAsStringAsync();
            Assert.StartsWith("The client name is not valid", Alert(html));
            Assert.DoesNotContain("<b>x</b>", html);
            Assert.DoesNotContain("gks_", html);
        }
        Assert.Empty(await ApiClientsAsync(api, app));

        // duplicate name: 409 with a fixed text and no secret
        var name = Unique("dup");
        await CreateClientAsync(api, name, app);
        var dup = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.Conflict, dup.StatusCode);
        var dupHtml = await dup.Content.ReadAsStringAsync();
        Assert.Equal("A client with that name already exists.", Alert(dupHtml));
        Assert.DoesNotContain("gks_", dupHtml);
        Assert.Contains("name=\"Name\"", dupHtml); // the form is still there
        Assert.Single(await ApiClientsAsync(api, app));
    }

    [Fact]
    public async Task A_stale_edit_form_does_not_undo_another_admins_change_and_a_missing_checkbox_means_unchanged()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("stale"));
        var name = Unique("old");
        var (id, _) = await CreateClientAsync(api, name, app);

        var page = await b.GetStringAsync($"/Clients/Edit/{id}");
        Assert.Contains("name=\"OrigName\"", page);
        Assert.Contains("<input type=\"hidden\" name=\"IsActive\" value=\"false\"", page);
        // meanwhile another administrator disables the client
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/clients/{id}", new { isActive = false })).StatusCode);
        // the stale form (still showing "active") renames only
        var newName = Unique("new");
        var r = await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = newName, ["IsActive"] = "true", ["OrigName"] = name, ["OrigIsActive"] = "true" }, $"/Clients/Edit/{id}");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var now = await ApiClientAsync(api, id);
        Assert.Equal(newName, now.GetProperty("name").GetString());
        Assert.False(now.GetProperty("isActive").GetBoolean());

        // another admin renames; a stale form that only unchecks "active" must not bring back the old name
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/clients/{id}", new { isActive = true, name = "renamed-meanwhile" })).StatusCode);
        var r2 = await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = newName, ["IsActive"] = "false", ["OrigName"] = newName, ["OrigIsActive"] = "true" }, $"/Clients/Edit/{id}");
        Assert.Equal(HttpStatusCode.Redirect, r2.StatusCode);
        now = await ApiClientAsync(api, id);
        Assert.Equal("renamed-meanwhile", now.GetProperty("name").GetString());
        Assert.False(now.GetProperty("isActive").GetBoolean());

        // a hand-made POST without IsActive (and without a snapshot) changes nothing it was not asked to
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/clients/{id}", new { isActive = true })).StatusCode);
        var r3 = await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = "renamed-meanwhile" }, $"/Clients/Edit/{id}");
        Assert.Equal(HttpStatusCode.Redirect, r3.StatusCode);
        Assert.True((await ApiClientAsync(api, id)).GetProperty("isActive").GetBoolean());
        // a rename without IsActive keeps it active
        await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = "again-renamed" }, $"/Clients/Edit/{id}");
        now = await ApiClientAsync(api, id);
        Assert.Equal("again-renamed", now.GetProperty("name").GetString());
        Assert.True(now.GetProperty("isActive").GetBoolean());

        // refused rename: bad name 400, duplicate 409; both with fixed texts
        var other = Unique("other");
        await CreateClientAsync(api, other, app);
        var bad = await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = "Bad Name", ["IsActive"] = "true" }, $"/Clients/Edit/{id}");
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.StartsWith("The client name is not valid", Alert(await bad.Content.ReadAsStringAsync()));
        var dup = await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = other, ["IsActive"] = "true" }, $"/Clients/Edit/{id}");
        Assert.Equal(HttpStatusCode.Conflict, dup.StatusCode);
        Assert.Equal("A client with that name already exists.", Alert(await dup.Content.ReadAsStringAsync()));
        Assert.Equal("again-renamed", (await ApiClientAsync(api, id)).GetProperty("name").GetString());
    }

    [Fact]
    public async Task Refusals_and_outages_show_fixed_texts_and_the_api_wording_is_only_logged()
    {
        var log = new CaptureLog();
        HttpStatusCode? armed = null;
        WebFixture? f = null;
        f = new WebFixture(false, s =>
        {
            s.AddSingleton<ILoggerProvider>(log);
            s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
                armed is { } code && r.Method != HttpMethod.Get && r.RequestUri!.AbsolutePath.StartsWith("/v1/clients", StringComparison.Ordinal)
                    ? new HttpResponseMessage(code) { Content = new StringContent("{\"detail\":\"internal-wording\\u0007xyz\"}", System.Text.Encoding.UTF8, "application/json") }
                    : null));
        });
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("map"));
        var (id, secret) = await CreateClientAsync(api, Unique("m"), app);
        await GiveRoleAsync(api, app, id);
        var paths = new (string Path, Dictionary<string, string> Fields, string Conflict)[]
        {
            ("/Clients/Create", new() { ["Name"] = Unique("n"), ["App"] = app.ToString() }, "The client could not be saved because of a conflict."),
            ($"/Clients/Edit/{id}", new() { ["Name"] = Unique("n"), ["IsActive"] = "true", ["OrigName"] = "x" }, "The client could not be saved because of a conflict."),
            ($"/Clients/Rotate/{id}", new(), "The secret could not be rotated."),
            ($"/Clients/Delete/{id}", new(), "The client could not be deleted."),
        };

        armed = HttpStatusCode.Conflict;
        foreach (var (path, fields, text) in paths)
        {
            var r = await WebFixture.PostFormAsync(b, path, new(fields), path);
            Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
            var body = await r.Content.ReadAsStringAsync();
            Assert.DoesNotContain("internal-wording", body);
            Assert.Equal(text, Alert(body));
        }
        Assert.Contains("internal-wordingxyz", string.Join('\n', log.Lines));
        Assert.DoesNotContain('\u0007', string.Join('\n', log.Lines));

        armed = HttpStatusCode.NotFound;
        foreach (var (path, fields, _) in paths.Skip(1))
            Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, path, new(fields), path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("n"), ["App"] = app.ToString() }, "/Clients/Create")).StatusCode);

        armed = HttpStatusCode.ServiceUnavailable;
        foreach (var (path, fields, _) in paths)
        {
            var r = await WebFixture.PostFormAsync(b, path, new(fields), path);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, r.StatusCode);
            var body = await r.Content.ReadAsStringAsync();
            Assert.DoesNotContain("internal-wording", body);
            Assert.DoesNotContain("gks_", body);
            if (path is "/Clients/Create" || path.StartsWith("/Clients/Rotate/", StringComparison.Ordinal))
                Assert.Equal(Gatekeeper.Web.Pages.Clients.ClientAccess.UncertainText, Alert(body)); // may have taken effect: a specific text, not the generic error page
        }
        armed = null;
        // nothing happened: same client, same secret
        Assert.Single(await ApiClientsAsync(api, app));
        Assert.Equal(HttpStatusCode.OK, await ClientTokenAsync(f, (await ApiClientAsync(api, id)).GetProperty("name").GetString()!, secret));
    }

    [Fact]
    public async Task Hostile_text_from_the_api_is_encoded()
    {
        const string Evil = "<script>alert(1)</script>";
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method != HttpMethod.Get || !path.StartsWith("/v1/clients", StringComparison.Ordinal)) return null;
            var item = $"{{\"id\":\"{Guid.Empty}\",\"name\":\"{Evil}\",\"appId\":\"{Guid.NewGuid()}\",\"isActive\":true,\"createdAt\":\"2026-01-01T00:00:00Z\",\"updatedAt\":\"2026-01-01T00:00:00Z\"}}";
            var json = path == "/v1/clients" ? $"{{\"items\":[{item}],\"nextCursor\":null}}" : item;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        foreach (var path in new[] { "/Clients", "/Clients/Edit/" + Guid.Empty, "/Clients/Delete/" + Guid.Empty, "/Clients/Rotate/" + Guid.Empty })
        {
            var html = await b.GetStringAsync(path);
            Assert.DoesNotContain(Evil, html);
            Assert.Contains("&lt;script&gt;", html);
        }
    }

    [Fact]
    public async Task The_secret_appears_in_exactly_one_response_and_in_no_log_audit_row_or_later_page()
    {
        var log = new CaptureLog();
        using var f = new WebFixture(false, s => s.AddSingleton<ILoggerProvider>(log));
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("leak"));
        var name = Unique("lk");
        var seen = new List<string>(); // everything the browser received after the secret pages: headers and bodies
        async Task<string> GetAsync(string path)
        {
            var r = await b.GetAsync(path);
            var text = HeadersOf(r) + "\n" + await r.Content.ReadAsStringAsync();
            seen.Add(text);
            return text;
        }

        var created = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" });
        var createdText = HeadersOf(created) + "\n" + await created.Content.ReadAsStringAsync();
        var secret1 = SecretShape().Match(createdText).Value;
        Assert.Single(SecretShape().Matches(createdText));
        var id = Assert.Single(await ApiClientsAsync(api, app)).GetProperty("id").GetGuid();

        // the same flow again for the rotated secret
        await GetAsync("/Clients");
        await GetAsync("/Clients/Create");
        await GetAsync($"/Clients/Edit/{id}");
        var rotated = await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        var rotatedText = HeadersOf(rotated) + "\n" + await rotated.Content.ReadAsStringAsync();
        var secret2 = SecretShape().Match(rotatedText).Value;
        Assert.Single(SecretShape().Matches(rotatedText));
        Assert.NotEqual(secret1, secret2);
        Assert.DoesNotContain(secret1, rotatedText);

        // reload/back: plain GETs, the list, edit and the other pages never show either secret
        foreach (var path in new[] { "/Clients", $"/Clients?app={app}", "/Clients/Create", $"/Clients/Edit/{id}", $"/Clients/Rotate/{id}", $"/Clients/Delete/{id}", "/Applications", "/Users" })
            await GetAsync(path);
        // the browser's resubmit: a duplicate name (409) and another rotation, with fresh antiforgery tokens
        var resubmit = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.Conflict, resubmit.StatusCode);
        seen.Add(HeadersOf(resubmit) + "\n" + await resubmit.Content.ReadAsStringAsync());
        // an edit and a delete
        seen.Add(HeadersOf(await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = name + "-2" }, $"/Clients/Edit/{id}")));
        seen.Add(HeadersOf(await WebFixture.PostFormAsync(b, $"/Clients/Delete/{id}", new())));

        foreach (var text in seen)
        {
            Assert.DoesNotContain(secret1, text);
            Assert.DoesNotContain(secret2, text);
        }
        var lines = string.Join('\n', log.Lines);
        Assert.DoesNotContain(secret1, lines);
        Assert.DoesNotContain(secret2, lines);
        Assert.DoesNotContain("gks_", lines);
        var audit = await api.GetStringAsync("/v1/audit?limit=200");
        Assert.DoesNotContain(secret1, audit);
        Assert.DoesNotContain(secret2, audit);
        Assert.DoesNotContain("gks_", audit);
        // the secret is not stored anywhere the UI can reach: the API itself no longer returns it
        Assert.DoesNotContain("gks_", await api.GetStringAsync($"/v1/clients?limit=200"));
    }

    [Fact]
    public async Task Client_changes_are_audited_under_the_signed_in_admin()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("aud"));
        var name = Unique("au");
        await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" });
        var id = Assert.Single(await ApiClientsAsync(api, app)).GetProperty("id").GetGuid();
        await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = name + "x", ["IsActive"] = "true", ["OrigName"] = name, ["OrigIsActive"] = "true" }, $"/Clients/Edit/{id}");
        await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        await WebFixture.PostFormAsync(b, $"/Clients/Delete/{id}", new());
        var me = (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + WebFixture.AdminName)).GetProperty("items")[0].GetProperty("id").GetString();
        var rows = JsonDocument.Parse(await api.GetStringAsync("/v1/audit?limit=200")).RootElement.GetProperty("items").EnumerateArray().ToList();
        foreach (var action in new[] { "PATCH /v1/clients/{id}", "POST /v1/clients/{id}/secret", "DELETE /v1/clients/{id}" })
        {
            var row = Assert.Single(rows, e => e.GetProperty("action").GetString() == action && (e.GetProperty("target").GetString() ?? "").Contains(id.ToString()));
            Assert.Equal(me, row.GetProperty("actor").GetString());
        }
        var create = rows.Where(e => e.GetProperty("action").GetString() == "POST /v1/clients").ToList();
        Assert.Contains(create, e => e.GetProperty("actor").GetString() == me);
    }

    [Fact]
    public async Task The_list_pages_and_filters_by_application_and_keeps_the_filter()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var appA = await CreateAppAsync(api, Unique("fa"));
        var appB = await CreateAppAsync(api, Unique("fb"));
        for (var i = 0; i < 27; i++) await CreateClientAsync(api, $"a-{i:D2}", appA);
        await CreateClientAsync(api, "b-only", appB);

        var all = await b.GetStringAsync("/Clients");
        Assert.Contains("Next page", all);
        Assert.Contains("b-only", all + await b.GetStringAsync(Regex.Match(all, "href=\"(/Clients\\?[^\"]+)\"").Groups[1].Value.Replace("&amp;", "&")));

        var filtered = await b.GetStringAsync($"/Clients?app={appA}");
        Assert.DoesNotContain("b-only", filtered);
        Assert.Equal(25, Regex.Matches(filtered, "<td>a-\\d\\d</td>").Count);
        Assert.Contains($"<option value=\"{appA}\" selected", filtered);
        var next = Regex.Match(filtered, "href=\"(/Clients\\?[^\"]+)\">Next page").Groups[1].Value.Replace("&amp;", "&");
        Assert.Contains($"app={appA}", next);
        var second = await b.GetStringAsync(next);
        Assert.Equal(2, Regex.Matches(second, "<td>a-\\d\\d</td>").Count);
        Assert.DoesNotContain("b-only", second);
        Assert.DoesNotContain("Next page", second);
        Assert.Contains("b-only", await b.GetStringAsync($"/Clients?app={appB}"));
        // the page of an application with none, an unknown application and a garbage filter
        Assert.Contains("No clients.", await b.GetStringAsync($"/Clients?app={Guid.NewGuid()}"));
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Clients?app=garbage")).StatusCode);
        // an edited cursor goes back to the first page of the same filter
        var bad = await b.GetAsync($"/Clients?app={appA}&cursor=garbage");
        Assert.Equal(HttpStatusCode.Redirect, bad.StatusCode);
        Assert.Equal($"/Clients?app={appA}", bad.Headers.Location?.OriginalString);
        // the reserved application is not a filter choice
        Assert.DoesNotContain(">gatekeeper</option>", all);
    }

    [Fact]
    public async Task A_crafted_post_to_the_list_is_a_404_and_the_nav_has_a_clients_entry()
    {
        var b = await _f.SignedInAsync();
        var r = await WebFixture.PostFormAsync(b, "/Clients", new() { ["Name"] = "x" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        Assert.Contains("<a href=\"/Clients\">Clients</a>", await b.GetStringAsync("/Users"));
    }

    [Fact]
    public async Task The_list_shows_fixed_texts_when_the_api_fails()
    {
        WebFixture? f = null;
        HttpStatusCode? armed = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed is { } c && r.RequestUri!.AbsolutePath.StartsWith("/v1/clients", StringComparison.Ordinal) ? new HttpResponseMessage(c) { Content = new StringContent("{\"detail\":\"internal-wording\"}", System.Text.Encoding.UTF8, "application/json") } : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        armed = HttpStatusCode.Conflict;
        var conflict = await b.GetAsync("/Clients");
        Assert.Equal(HttpStatusCode.OK, conflict.StatusCode);
        var html = await conflict.Content.ReadAsStringAsync();
        Assert.Equal("Could not list clients.", Alert(html));
        Assert.DoesNotContain("internal-wording", html);
        armed = HttpStatusCode.ServiceUnavailable;
        var down = await b.GetAsync("/Clients");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, down.StatusCode);
        Assert.DoesNotContain("internal-wording", await down.Content.ReadAsStringAsync());
        armed = HttpStatusCode.NotFound;
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Clients")).StatusCode);
    }
}
