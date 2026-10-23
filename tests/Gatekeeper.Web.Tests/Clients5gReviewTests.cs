extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeeper.Web.Pages.Clients;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Fixes from the review of slice 5g: real browser checkbox bodies, one-time form values, wording, request counts.</summary>
public partial class Clients5gReviewTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Clients5gReviewTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    [GeneratedRegex("gks_[A-Za-z0-9_-]{43}")]
    private static partial Regex SecretShape();

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

    private static async Task<bool> ClientActiveAsync(HttpClient api, Guid id) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{id}")).GetProperty("isActive").GetBoolean();

    private static async Task<bool> UserActiveAsync(HttpClient api, Guid id) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{id}")).GetProperty("isActive").GetBoolean();

    private static Task<HttpResponseMessage> RawPostAsync(HttpClient b, string path, string body) =>
        b.PostAsync(path, new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

    private static string Q(string s) => Uri.EscapeDataString(s);

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static async Task<(string Name, Guid Id)> NewUserAsync(HttpClient api, bool active)
    {
        var name = Unique("ru");
        var r = await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "person" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        if (!active) Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false })).StatusCode);
        return (name, id);
    }

    // ---- 1. checkbox bodies exactly as a browser sends them ----

    [Fact]
    public void FormFlag_any_true_wins_and_nothing_is_null()
    {
        Assert.True(FormFlag.Parse(["false", "true"]));
        Assert.True(FormFlag.Parse(["true", "false"]));
        Assert.True(FormFlag.Parse(["TRUE"]));
        Assert.False(FormFlag.Parse(["false"]));
        Assert.Null(FormFlag.Parse(null));
        Assert.Null(FormFlag.Parse([]));
        Assert.Null(FormFlag.Parse(["maybe"]));
    }

    [Fact]
    public async Task Create_client_form_ticked_means_active_and_unticked_means_inactive()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("cb"));
        var ticked = Unique("t");
        var unticked = Unique("u");
        var (tok, nonce) = await WebFixture.TokenAndNonceAsync(b, "/Clients/Create");
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q(tok)}&Nonce={Q(nonce!)}&Name={ticked}&App={app}&IsActive=false&IsActive=true")).StatusCode);
        (tok, nonce) = await WebFixture.TokenAndNonceAsync(b, "/Clients/Create");
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q(tok)}&Nonce={Q(nonce!)}&Name={unticked}&App={app}&IsActive=false")).StatusCode);
        var items = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray().ToList();
        Assert.True(items.Single(i => i.GetProperty("name").GetString() == ticked).GetProperty("isActive").GetBoolean());
        Assert.False(items.Single(i => i.GetProperty("name").GetString() == unticked).GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task Edit_client_form_keeps_an_active_client_active_when_only_the_name_changes_and_toggles_both_ways()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("eb"));
        var name = Unique("e");
        var (id, _) = await CreateClientAsync(api, name, app);
        var edit = $"/Clients/Edit/{id}";

        var renamed = Unique("r");
        var tok = await WebFixture.TokenAsync(b, edit);
        Assert.Equal(HttpStatusCode.Redirect, (await RawPostAsync(b, edit, $"__RequestVerificationToken={Q(tok)}&OrigName={name}&OrigIsActive=true&Name={renamed}&IsActive=false&IsActive=true&Version={await WebFixture.VersionOfAsync(b, edit)}")).StatusCode);
        Assert.True(await ClientActiveAsync(api, id), "an unchanged-but-ticked client must stay active");
        Assert.Equal(renamed, (await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{id}")).GetProperty("name").GetString());

        tok = await WebFixture.TokenAsync(b, edit);
        await RawPostAsync(b, edit, $"__RequestVerificationToken={Q(tok)}&OrigName={renamed}&OrigIsActive=true&Name={renamed}&IsActive=false&Version={await WebFixture.VersionOfAsync(b, edit)}");
        Assert.False(await ClientActiveAsync(api, id));
        tok = await WebFixture.TokenAsync(b, edit);
        await RawPostAsync(b, edit, $"__RequestVerificationToken={Q(tok)}&OrigName={renamed}&OrigIsActive=false&Name={renamed}&IsActive=false&IsActive=true&Version={await WebFixture.VersionOfAsync(b, edit)}");
        Assert.True(await ClientActiveAsync(api, id));
    }

    [Fact]
    public async Task Edit_user_form_keeps_an_active_user_active_when_another_field_is_saved_and_toggles_both_ways()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var (name, id) = await NewUserAsync(api, active: true);
        var edit = $"/Users/Edit/{id}";
        string Body(string token, string display, string orig, string active, string version) =>
            $"__RequestVerificationToken={Q(token)}&OrigUsername={name}&OrigEmail={name}%40example.com&OrigDisplayName=&OrigKind=person&OrigExpiry=&OrigIsActive={orig}" +
            $"&Username={name}&Email={name}%40example.com&DisplayName={display}&Kind=person&Expiry=&{active}&Version={version}";

        var saved = await RawPostAsync(b, edit, Body(await WebFixture.TokenAsync(b, edit), "Changed", "true", "IsActive=false&IsActive=true", (await WebFixture.VersionOfAsync(b, edit))!));
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        Assert.True(await UserActiveAsync(api, id), "saving another field must not disable an active user");
        Assert.Equal("Changed", (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{id}")).GetProperty("displayName").GetString());

        Assert.Equal(HttpStatusCode.Redirect, (await RawPostAsync(b, edit, Body(await WebFixture.TokenAsync(b, edit), "Changed", "true", "IsActive=false", (await WebFixture.VersionOfAsync(b, edit))!))).StatusCode);
        Assert.False(await UserActiveAsync(api, id));
        Assert.Equal(HttpStatusCode.Redirect, (await RawPostAsync(b, edit, Body(await WebFixture.TokenAsync(b, edit), "Changed", "false", "IsActive=false&IsActive=true", (await WebFixture.VersionOfAsync(b, edit))!))).StatusCode);
        Assert.True(await UserActiveAsync(api, id));
    }

    // ---- 3. one-time form values ----

    [Fact]
    public async Task Resubmitting_a_rotate_does_not_rotate_again_and_shows_the_fixed_text_with_a_fresh_form()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("rr"));
        var name = Unique("r");
        var (id, _) = await CreateClientAsync(api, name, app);
        var role = (await (await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "reader", description = "d" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        await api.PutAsync($"/v1/clients/{id}/roles/{role}", null);
        var path = $"/Clients/Rotate/{id}";

        var (tok, nonce) = await WebFixture.TokenAndNonceAsync(b, path);
        Assert.NotNull(nonce);
        var body = $"__RequestVerificationToken={Q(tok)}&Nonce={Q(nonce)}";
        var first = await RawPostAsync(b, path, body);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstSecret = SecretShape().Match(await first.Content.ReadAsStringAsync()).Value;
        Assert.NotEmpty(firstSecret);

        var again = await RawPostAsync(b, path, body); // the browser's "resend the form"
        var text = await again.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.DoesNotContain("gks_", text);
        Assert.Equal(ClientAccess.AlreadyDoneText, Alert(text));
        Assert.Matches("name=\"Nonce\"[^>]*value=\"[^\"]+\"", text);
        Assert.NotEqual(nonce, Regex.Match(text, "name=\"Nonce\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);

        var token = await f_ClientTokenAsync(name, firstSecret);
        Assert.Equal(HttpStatusCode.OK, token); // the first rotation's secret is still the valid one
    }

    private async Task<HttpStatusCode> f_ClientTokenAsync(string name, string secret) =>
        (await _f.Api.CreateClient().PostAsJsonAsync("/v1/auth/client-token", new { clientId = name, clientSecret = secret })).StatusCode;

    [Fact]
    public async Task A_missing_or_foreign_nonce_never_calls_the_api()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("nn"));
        var (id, secret) = await CreateClientAsync(api, Unique("n"), app);
        var other = Unique("o");
        // no nonce at all
        var tok = await WebFixture.TokenAsync(b, $"/Clients/Rotate/{id}");
        var r = await RawPostAsync(b, $"/Clients/Rotate/{id}", $"__RequestVerificationToken={Q(tok)}");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        // a nonce of the create form does not work for a rotate
        var (_, createNonce) = await WebFixture.TokenAndNonceAsync(b, "/Clients/Create");
        tok = await WebFixture.TokenAsync(b, $"/Clients/Rotate/{id}");
        Assert.Equal(HttpStatusCode.Conflict, (await RawPostAsync(b, $"/Clients/Rotate/{id}", $"__RequestVerificationToken={Q(tok)}&Nonce={Q(createNonce!)}")).StatusCode);
        // a missing nonce on create creates nothing
        tok = await WebFixture.TokenAsync(b, "/Clients/Create");
        Assert.Equal(HttpStatusCode.Conflict, (await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q(tok)}&Name={other}&App={app}&IsActive=true")).StatusCode);
        var items = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray().ToList();
        Assert.Single(items);
        // the original secret still works (nothing was rotated)
        await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "reader", description = "d" });
        var name = items[0].GetProperty("name").GetString()!;
        var role = (await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{app}/roles")).GetProperty("items")[0].GetProperty("id").GetGuid();
        await api.PutAsync($"/v1/clients/{id}/roles/{role}", null);
        Assert.Equal(HttpStatusCode.OK, await f_ClientTokenAsync(name, secret));
    }

    [Fact]
    public async Task A_double_create_leaves_no_orphan_even_when_the_name_was_changed()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("dc"));
        var (tok, nonce) = await WebFixture.TokenAndNonceAsync(b, "/Clients/Create");
        var first = await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q(tok)}&Nonce={Q(nonce!)}&Name={Unique("a")}&App={app}&IsActive=true");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Contains("gks_", await first.Content.ReadAsStringAsync());
        // resend with a different name (the browser let the user edit it): still refused
        var second = await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q(tok)}&Nonce={Q(nonce!)}&Name={Unique("b")}&App={app}&IsActive=true");
        var text = await second.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.DoesNotContain("gks_", text);
        Assert.Equal(ClientAccess.AlreadyDoneText, Alert(text));
        Assert.Single((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task A_concurrent_double_submit_calls_the_api_once()
    {
        var calls = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (r.Method == HttpMethod.Post && r.RequestUri!.AbsolutePath.EndsWith("/secret", StringComparison.Ordinal)) Interlocked.Increment(ref calls);
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("cc"));
        var (id, _) = await CreateClientAsync(api, Unique("c"), app);
        var path = $"/Clients/Rotate/{id}";
        var (tok, nonce) = await WebFixture.TokenAndNonceAsync(b, path);
        var body = $"__RequestVerificationToken={Q(tok)}&Nonce={Q(nonce!)}";
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => RawPostAsync(b, path, body)));
        Assert.Equal(1, calls);
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(7, results.Count(r => r.StatusCode == HttpStatusCode.Conflict));
    }

    [Fact]
    public void Nonces_are_one_time_per_purpose_and_bounded()
    {
        var s = new WebSession("id", "u", new Tokens("a", DateTimeOffset.MaxValue, "r", DateTimeOffset.MaxValue), DateTimeOffset.UtcNow);
        var n = s.IssueNonce("p");
        Assert.False(s.ConsumeNonce("q", n));
        Assert.True(s.ConsumeNonce("p", n));
        Assert.False(s.ConsumeNonce("p", n));
        Assert.False(s.ConsumeNonce("p", null));
        var first = s.IssueNonce("p");
        for (var i = 0; i < 100; i++) s.IssueNonce("p");
        Assert.False(s.ConsumeNonce("p", first)); // the oldest was forgotten
    }

    // ---- 2. outcome unknown ----

    [Fact]
    public async Task A_gateway_timeout_on_create_or_rotate_shows_the_specific_text()
    {
        HttpStatusCode? armed = null;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed is { } code && r.Method == HttpMethod.Post && r.RequestUri!.AbsolutePath.StartsWith("/v1/clients", StringComparison.Ordinal) ? new HttpResponseMessage(code) : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("to"));
        var (id, _) = await CreateClientAsync(api, Unique("t"), app);
        armed = HttpStatusCode.InternalServerError;
        var create = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("n"), ["App"] = app.ToString() });
        Assert.Equal(ClientAccess.UncertainText, Alert(await create.Content.ReadAsStringAsync()));
        var rotate = await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        var text = await rotate.Content.ReadAsStringAsync();
        Assert.Equal(ClientAccess.UncertainText, Alert(text));
        Assert.Matches("name=\"Nonce\"", text); // a fresh confirmation to try again
    }

    // ---- 4/5. wording and confirmation pages ----

    [Fact]
    public async Task Rotate_and_delete_pages_show_application_state_and_a_stronger_warning_for_an_active_client()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var appName = Unique("shop");
        var app = await CreateAppAsync(api, appName);
        var (active, _) = await CreateClientAsync(api, Unique("a"), app);
        var (inactive, _) = await CreateClientAsync(api, Unique("i"), app, active: false);
        foreach (var page in new[] { "Rotate", "Delete" })
        {
            var a = await b.GetStringAsync($"/Clients/{page}/{active}");
            Assert.Contains(appName, a);
            Assert.Contains("<strong>yes</strong>", a);
            Assert.Contains("This client is active", Alert(a));
            var i = await b.GetStringAsync($"/Clients/{page}/{inactive}");
            Assert.Contains(appName, i);
            Assert.Contains("<strong>no</strong>", i);
            Assert.Equal("", Alert(i));
            Assert.Contains("validate tokens locally", i);
        }
        var rotate = await b.GetStringAsync($"/Clients/Rotate/{active}");
        Assert.Contains("keep the client disabled until the access-token lifetime has passed", rotate);
        Assert.Contains("enabling it again revives the tokens", rotate);
        var edit = await b.GetStringAsync($"/Clients/Edit/{active}");
        Assert.Contains("only while it stays disabled", edit);
    }

    [Fact]
    public async Task The_secret_page_has_no_misleading_duplicate_hint_and_asks_the_browser_to_drop_its_cache_but_not_cookies()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("sp"));
        var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("s"), ["App"] = app.ToString(), ["IsActive"] = "true" });
        var text = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain("duplicate", text);
        Assert.Equal("\"cache\"", r.Headers.GetValues("Clear-Site-Data").Single());
        // the session survives: the next page still renders for the same browser
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Clients")).StatusCode);
        // other pages do not send it
        Assert.False((await b.GetAsync("/Clients")).Headers.Contains("Clear-Site-Data"));
    }

    // ---- 7. request counts ----

    [Fact]
    public async Task The_client_list_does_not_re_read_applications_on_every_view_and_names_resolve()
    {
        var appCalls = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath.StartsWith("/v1/applications", StringComparison.Ordinal)) Interlocked.Increment(ref appCalls);
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var appName = Unique("lst");
        var app = await CreateAppAsync(api, appName);
        await CreateClientAsync(api, Unique("c"), app);
        var first = await b.GetStringAsync("/Clients");
        Assert.Contains($"<td>{appName}</td>", first);
        var afterFirst = appCalls;
        Assert.Equal(1, afterFirst); // one list call: the names come from it, no per-row lookups
        for (var i = 0; i < 3; i++) Assert.Contains($"<td>{appName}</td>", await b.GetStringAsync("/Clients"));
        Assert.Equal(afterFirst, appCalls); // cached for a few seconds
        // the create form always reads afresh
        var before = appCalls;
        await b.GetStringAsync("/Clients/Create");
        Assert.True(appCalls > before);
    }

    // ---- 8. 400 texts by cause ----

    [Fact]
    public async Task A_name_problem_gets_the_name_rules_and_any_other_bad_request_a_generic_text()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("bq"));
        var bad = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = "Bad Name!", ["App"] = app.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal(ClientAccess.NameRulesText, WebUtility.HtmlDecode(Alert(await bad.Content.ReadAsStringAsync())));

        Assert.Equal(ClientAccess.NameRulesText, ClientAccess.SaveRefusalText(new ApiException(HttpStatusCode.BadRequest, "name must be lowercase")));
        Assert.Equal(ClientAccess.GenericBadRequestText, ClientAccess.SaveRefusalText(new ApiException(HttpStatusCode.BadRequest, "application is required.")));
        Assert.Equal(ClientAccess.GenericBadRequestText, ClientAccess.SaveRefusalText(new ApiException(HttpStatusCode.BadRequest, "Bad Request")));
    }

    // ---- final review fixes ----

    [Fact]
    public async Task A_non_json_success_answer_to_create_or_rotate_is_uncertain()
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed && r.Method == HttpMethod.Post && r.RequestUri!.AbsolutePath.StartsWith("/v1/clients", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>proxy</html>", Encoding.UTF8, "text/html") }
                : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("nj"));
        var (id, _) = await CreateClientAsync(api, Unique("t"), app);
        armed = true;
        var create = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("n"), ["App"] = app.ToString() });
        Assert.Equal(HttpStatusCode.BadGateway, create.StatusCode);
        Assert.Equal(ClientAccess.UncertainText, Alert(await create.Content.ReadAsStringAsync()));
        var rotate = await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        Assert.Equal(HttpStatusCode.BadGateway, rotate.StatusCode);
        Assert.Equal(ClientAccess.UncertainText, Alert(await rotate.Content.ReadAsStringAsync()));
    }

    [Fact]
    public async Task The_app_list_snapshot_is_dropped_when_expired_and_not_stored_after_an_invalidation()
    {
        var s = new WebSession("id", "u", new Tokens("a", DateTimeOffset.MaxValue, "r", DateTimeOffset.MaxValue), DateTimeOffset.UtcNow);
        var old = new AppListSnapshot(DateTimeOffset.UtcNow, [], []);
        s.TryStoreAppList(old, s.AppListVersion);
        Assert.Same(old, s.AppList);
        s.DropAppList(old);
        Assert.Null(s.AppList);
        var version = s.AppListVersion; // a read starts ...
        s.InvalidateAppList(); // ... an application is deleted meanwhile ...
        s.TryStoreAppList(old, version); // ... the late result is not kept
        Assert.Null(s.AppList);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task A_refused_create_form_keeps_what_was_typed_and_uses_the_neutral_text()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("nk"));
        var name = Unique("keep");
        var r = await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q((await WebFixture.TokenAndNonceAsync(b, "/Clients/Create")).Item1)}&Nonce=stale&Name={name}&App={app}&IsActive=true");
        var text = await r.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal("This form has expired or was already used. The secret is not shown again. Check the client list before trying again.", Alert(text));
        Assert.Contains($"value=\"{name}\"", text);
        Assert.Matches($"<option[^>]*value=\"{app}\"[^>]*selected", text);
        Assert.Empty((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task A_refused_edit_after_a_post_without_the_flag_keeps_the_checkbox_as_the_current_state()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("rf"));
        var (cid, _) = await CreateClientAsync(api, Unique("c"), app);
        var cPath = $"/Clients/Edit/{cid}";
        var (t1, _) = await WebFixture.TokenAndNonceAsync(b, cPath);
        var c = await RawPostAsync(b, cPath, $"__RequestVerificationToken={Q(t1)}&Name=Bad%20Name!&Version={await WebFixture.VersionOfAsync(b, cPath)}");
        var ctext = await c.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, c.StatusCode);
        Assert.Matches("<input type=\"checkbox\" name=\"IsActive\"[^>]*checked", ctext);

        var u = Unique("u");
        var created = await api.PostAsJsonAsync("/v1/users", new { username = u, email = $"{u}@example.com", displayName = "x", kind = "person" });
        var uid = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var uPath = $"/Users/Edit/{uid}";
        var (t2, _) = await WebFixture.TokenAndNonceAsync(b, uPath);
        var ur = await RawPostAsync(b, uPath, $"__RequestVerificationToken={Q(t2)}&Username={u}&Email={u}%40example.com&DisplayName=x&Kind=bogus&Expiry=&Version={await WebFixture.VersionOfAsync(b, uPath)}");
        var utext = await ur.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, ur.StatusCode); // a validation message, no API call
        Assert.Contains("Kind must be", utext);
        Assert.Matches("<input type=\"checkbox\" name=\"IsActive\"[^>]*checked", utext);
        Assert.True(await UserActiveAsync(api, uid));
        Assert.True(await ClientActiveAsync(api, cid));
    }

    [Theory]
    [InlineData("yes")]
    [InlineData("1")]
    [InlineData("")]
    public async Task Create_with_an_IsActive_value_that_is_not_true_or_false_is_a_generic_bad_request(string value)
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("bv"));
        var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("n"), ["App"] = app.ToString(), ["IsActive"] = value }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal(ClientAccess.GenericBadRequestText, Alert(await r.Content.ReadAsStringAsync()));
        Assert.Empty((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Create_without_the_IsActive_field_still_defaults_to_active()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("bd"));
        var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("n"), ["App"] = app.ToString() }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var item = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray().Single();
        Assert.True(item.GetProperty("isActive").GetBoolean());
    }
}
