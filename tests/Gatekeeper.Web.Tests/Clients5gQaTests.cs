extern alias api;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent verification of slice 5g (clients and the one-time secret), written from the status.md spec.</summary>
public partial class Clients5gQaTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Clients5gQaTests(WebFixture f) => _f = f;

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

    private static async Task<Guid> IdOf(HttpResponseMessage r)
    {
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<(Guid Id, string Secret)> NewClientAsync(HttpClient api, string name, Guid app, bool active = true)
    {
        var r = await api.PostAsJsonAsync("/v1/clients", new { name, application = app, isActive = active });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        var j = await r.Content.ReadFromJsonAsync<JsonElement>();
        return (j.GetProperty("id").GetGuid(), j.GetProperty("secret").GetString()!);
    }

    private static async Task<Guid> GiveRoleAsync(HttpClient api, Guid app, Guid client, string role = "reader")
    {
        var role1 = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = role, description = "d" }));
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/clients/{client}/roles/{role1}", null)).StatusCode);
        return role1;
    }

    private static async Task<(HttpStatusCode Status, string? Token)> TokenAsync(WebFixture f, string name, string secret)
    {
        var r = await f.Api.CreateClient().PostAsJsonAsync("/v1/auth/client-token", new { clientId = name, clientSecret = secret });
        return (r.StatusCode, r.IsSuccessStatusCode ? (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString() : null);
    }

    private static async Task<bool> ActiveAsync(WebFixture f, string callerName, string callerSecret, string token)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token }) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(callerName + ":" + callerSecret)));
        var r = await f.Api.CreateClient().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean();
    }

    private static async Task<JsonElement> ApiClientAsync(HttpClient api, Guid id) => await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{id}");

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static string HeadersOf(HttpResponseMessage r) =>
        string.Join('\n', r.Headers.Concat(r.Content.Headers).Select(h => h.Key + ": " + string.Join(',', h.Value)));

    // ---- the browser really sends the hidden "false" and the checked "true" together ----

    [Fact]
    public async Task A_real_browser_form_with_hidden_false_and_checked_true_means_active()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("bf") }));
        var name = Unique("br");
        var (token, nonce) = await WebFixture.TokenAndNonceAsync(b, "/Clients/Create");

        // checked: IsActive=false&IsActive=true (hidden first, in the order of the page)
        var checkedBody = $"__RequestVerificationToken={Uri.EscapeDataString(token)}&Nonce={Uri.EscapeDataString(nonce!)}&Name={name}&App={app}&IsActive=false&IsActive=true";
        var r = await b.PostAsync("/Clients/Create", new StringContent(checkedBody, Encoding.UTF8, "application/x-www-form-urlencoded"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var id = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items")[0].GetProperty("id").GetGuid();
        Assert.True((await ApiClientAsync(api, id)).GetProperty("isActive").GetBoolean(), "checked box on create must create an active client");

        // unchecked: only the hidden false
        var name2 = Unique("br");
        var (token2, nonce2) = await WebFixture.TokenAndNonceAsync(b, "/Clients/Create");
        await b.PostAsync("/Clients/Create", new StringContent($"__RequestVerificationToken={Uri.EscapeDataString(token2)}&Nonce={Uri.EscapeDataString(nonce2!)}&Name={name2}&App={app}&IsActive=false", Encoding.UTF8, "application/x-www-form-urlencoded"));
        var items = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray().ToList();
        Assert.False(items.Single(i => i.GetProperty("name").GetString() == name2).GetProperty("isActive").GetBoolean());

        // edit: untick (only false) disables, tick (false + true) enables
        var edit = $"/Clients/Edit/{id}";
        var t3 = await WebFixture.TokenAsync(b, edit);
        await b.PostAsync(edit, new StringContent($"__RequestVerificationToken={Uri.EscapeDataString(t3)}&OrigName={name}&OrigIsActive=true&Name={name}&IsActive=false&Version={await WebFixture.VersionOfAsync(b, edit)}", Encoding.UTF8, "application/x-www-form-urlencoded"));
        Assert.False((await ApiClientAsync(api, id)).GetProperty("isActive").GetBoolean());
        var t4 = await WebFixture.TokenAsync(b, edit);
        await b.PostAsync(edit, new StringContent($"__RequestVerificationToken={Uri.EscapeDataString(t4)}&OrigName={name}&OrigIsActive=false&Name={name}&IsActive=false&IsActive=true&Version={await WebFixture.VersionOfAsync(b, edit)}", Encoding.UTF8, "application/x-www-form-urlencoded"));
        Assert.True((await ApiClientAsync(api, id)).GetProperty("isActive").GetBoolean(), "checked box on edit must enable the client");
    }

    // ---- disabled / rotate / delete semantics on tokens ----

    [Fact]
    public async Task A_disabled_client_gets_no_token_and_a_client_created_disabled_stays_unusable_until_enabled()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("dis") }));
        var name = Unique("d");
        var created = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "false" });
        var secret = SecretShape().Match(await created.Content.ReadAsStringAsync()).Value;
        var id = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items")[0].GetProperty("id").GetGuid();
        await GiveRoleAsync(api, app, id);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(_f, name, secret)).Status);
        await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = name, ["IsActive"] = "true", ["OrigName"] = name, ["OrigIsActive"] = "false" }, $"/Clients/Edit/{id}");
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(_f, name, secret)).Status);
    }

    [Fact]
    public async Task Rotate_replaces_the_secret_but_issued_tokens_live_on_and_delete_ends_them()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("tok") }));
        var (watcher, watcherSecret) = await NewClientAsync(api, Unique("w"), app);
        await GiveRoleAsync(api, app, watcher, "w");
        var watcherName = (await ApiClientAsync(api, watcher)).GetProperty("name").GetString()!;
        var (id, secret) = await NewClientAsync(api, Unique("t"), app);
        await GiveRoleAsync(api, app, id);
        var name = (await ApiClientAsync(api, id)).GetProperty("name").GetString()!;
        var (_, token) = await TokenAsync(_f, name, secret);
        Assert.True(await ActiveAsync(_f, watcherName, watcherSecret, token!));

        var rotated = await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        var newSecret = SecretShape().Match(await rotated.Content.ReadAsStringAsync()).Value;
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(_f, name, secret)).Status);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(_f, name, newSecret)).Status);
        Assert.True(await ActiveAsync(_f, watcherName, watcherSecret, token!), "an already issued token must stay valid after rotation");

        // a second rotation (the browser's resubmit) is accepted, invalidates the one on screen, and shows a different secret
        var again = await WebFixture.PostFormAsync(b, $"/Clients/Rotate/{id}", new());
        var third = SecretShape().Match(await again.Content.ReadAsStringAsync()).Value;
        Assert.NotEqual(newSecret, third);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(_f, name, newSecret)).Status);

        // delete: role assignments go, the token stops passing introspection, the id is gone
        var del = await WebFixture.PostFormAsync(b, $"/Clients/Delete/{id}", new());
        Assert.Equal(HttpStatusCode.Redirect, del.StatusCode);
        Assert.False(await ActiveAsync(_f, watcherName, watcherSecret, token!));
        Assert.Equal(HttpStatusCode.NotFound, (await api.GetAsync($"/v1/clients/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(_f, name, third)).Status);
        // re-creating the name gives an unrelated identity: no roles are inherited
        var back = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" });
        var reSecret = SecretShape().Match(await back.Content.ReadAsStringAsync()).Value;
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(_f, name, reSecret)).Status); // no role, so no token
    }

    [Fact]
    public async Task Disabling_a_client_ends_its_issued_tokens_as_the_page_says()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("off") }));
        var (watcher, ws) = await NewClientAsync(api, Unique("w"), app);
        await GiveRoleAsync(api, app, watcher, "w");
        var wn = (await ApiClientAsync(api, watcher)).GetProperty("name").GetString()!;
        var (id, secret) = await NewClientAsync(api, Unique("t"), app);
        await GiveRoleAsync(api, app, id);
        var name = (await ApiClientAsync(api, id)).GetProperty("name").GetString()!;
        var (_, token) = await TokenAsync(_f, name, secret);
        Assert.Contains("stop passing introspection", await b.GetStringAsync($"/Clients/Edit/{id}"));
        await WebFixture.PostFormAsync(b, $"/Clients/Edit/{id}", new() { ["Name"] = name, ["IsActive"] = "false", ["OrigName"] = name, ["OrigIsActive"] = "true" }, $"/Clients/Edit/{id}");
        Assert.False(await ActiveAsync(_f, wn, ws, token!));
    }

    // ---- names, applications deleted meanwhile ----

    [Fact]
    public async Task Name_rules_trim_boundaries_and_duplicates_across_applications_and_case()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app1 = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("n1") }));
        var app2 = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("n2") }));
        var padded = Unique("pad");
        // surrounding whitespace is trimmed
        var ok = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = "  " + padded + "  ", ["App"] = app1.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(padded, (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app1}")).GetProperty("items")[0].GetProperty("name").GetString());
        // client names are global: same name in another application is a duplicate, also in another case
        foreach (var dup in new[] { padded, padded.ToUpperInvariant() })
        {
            var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = dup, ["App"] = app2.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
            Assert.True(r.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.BadRequest, $"{dup}: {(int)r.StatusCode}");
            Assert.DoesNotContain("gks_", await r.Content.ReadAsStringAsync());
        }
        Assert.Empty((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app2}")).GetProperty("items").EnumerateArray());
        // 64 characters pass, 65 do not; leading '-', '.', '_' and unicode do not
        var max = "a" + new string('b', 63);
        Assert.Equal(HttpStatusCode.OK, (await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = max, ["App"] = app2.ToString(), ["IsActive"] = "true" }, "/Clients/Create")).StatusCode);
        foreach (var bad in new[] { "a" + new string('b', 64), "-lead", ".lead", "_lead", "naïve", "tab\tname", "line\nbreak", "a b" })
        {
            var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = bad, ["App"] = app2.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.StartsWith("The client name is not valid", Alert(await r.Content.ReadAsStringAsync()));
        }
    }

    [Fact]
    public async Task An_application_deleted_while_the_form_was_open_gives_404_and_no_client_or_secret()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("gone") }));
        Assert.Contains(app.ToString(), await b.GetStringAsync("/Clients/Create"));
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/applications/{app}")).StatusCode);
        var r = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = Unique("late"), ["App"] = app.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        Assert.DoesNotContain("gks_", await r.Content.ReadAsStringAsync());
        // and the filter on that id is just an empty list
        var list = await b.GetAsync($"/Clients?app={app}");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
    }

    [Fact]
    public async Task A_filter_with_bad_ids_never_fails()
    {
        var b = await _f.SignedInAsync();
        foreach (var q in new[] { "app=", "app=%00", "app=" + new string('9', 5000), "app=<script>", "app=" + Guid.Empty, "app=a&app=b", "cursor=%ff%fe", "cursor=" + new string('x', 5000), "app=" + Guid.NewGuid() + "&cursor=zz", "done=<b>", "done=updated&done=deleted" })
        {
            var r = await b.GetAsync("/Clients?" + q);
            Assert.True((int)r.StatusCode < 500, $"{q}: {(int)r.StatusCode}");
            Assert.DoesNotContain("<script>", await r.Content.ReadAsStringAsync());
        }
    }

    // ---- the one-time secret: cookies, headers, records, resubmits, errors ----

    [Fact]
    public async Task The_secret_is_in_no_cookie_no_set_cookie_and_the_headers_forbid_caching()
    {
        var cookies = new List<string>();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("ck") }));
        // raw browser that records every Set-Cookie
        var raw = _f.Web.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        async Task<HttpResponseMessage> Send(HttpRequestMessage req)
        {
            if (cookies.Count > 0) req.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies.Select(c => c.Split(';')[0])));
            var r = await raw.SendAsync(req);
            if (r.Headers.TryGetValues("Set-Cookie", out var sc)) foreach (var c in sc) { cookies.RemoveAll(o => o.Split('=')[0] == c.Split('=')[0]); cookies.Add(c); }
            return r;
        }
        var lg = await Send(new HttpRequestMessage(HttpMethod.Get, "/Login"));
        var tok = WebUtilityDecode(Regex.Match(await lg.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        var signIn = await Send(new HttpRequestMessage(HttpMethod.Post, "/Login") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword, ["__RequestVerificationToken"] = tok }) });
        Assert.Equal(HttpStatusCode.Redirect, signIn.StatusCode);
        var form = await Send(new HttpRequestMessage(HttpMethod.Get, "/Clients/Create"));
        var formHtml = await form.Content.ReadAsStringAsync();
        var tok2 = WebUtilityDecode(Regex.Match(formHtml, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        var nonce = WebUtilityDecode(Regex.Match(formHtml, "name=\"Nonce\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        var created = await Send(new HttpRequestMessage(HttpMethod.Post, "/Clients/Create") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = Unique("ck"), ["App"] = app.ToString(), ["IsActive"] = "true", ["__RequestVerificationToken"] = tok2, ["Nonce"] = nonce }) });
        var text = await created.Content.ReadAsStringAsync();
        var secret = SecretShape().Match(text).Value;
        Assert.NotEmpty(secret);
        Assert.False(created.Headers.Contains("Set-Cookie"), "the secret response must not set a cookie");
        foreach (var c in cookies) Assert.DoesNotContain(secret, Uri.UnescapeDataString(c));
        Assert.DoesNotContain(secret, HeadersOf(created));
        var cc = created.Headers.CacheControl!;
        Assert.True(cc.NoStore);
        Assert.Equal("no-cache", created.Headers.Pragma.ToString());
        Assert.Equal("no-referrer", created.Headers.GetValues("Referrer-Policy").Single());
        Assert.Null(created.Headers.Location);
        // no link or form on the secret page carries it, and no <meta refresh>
        Assert.DoesNotMatch("(href|action|src)=\"[^\"]*gks_", text);
        Assert.DoesNotContain("http-equiv", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<script", text, StringComparison.OrdinalIgnoreCase);
        Assert.Single(Regex.Matches(text, Regex.Escape(secret)));
        // follow-up requests with those cookies never see it
        foreach (var p in new[] { "/Clients", "/Clients/Create", "/Applications" })
            Assert.DoesNotContain(secret, await (await Send(new HttpRequestMessage(HttpMethod.Get, p))).Content.ReadAsStringAsync());
    }

    private static string WebUtilityDecode(string s) => WebUtility.HtmlDecode(s);

    [Fact]
    public void Records_and_exceptions_never_print_the_secret()
    {
        const string S = "gks_SECRETSECRETSECRETSECRETSECRETSECRETSECRE0";
        var id = Guid.NewGuid();
        var objs = new object[]
        {
            new SecretDto(S),
            new ClientCreatedDto(id, "n", id, true, S),
            new Gatekeeper.Web.Pages.Clients.SecretView(id, "n", S, true),
            new Gatekeeper.Web.Pages.Clients.SecretView(id, "n", S, false),
        };
        foreach (var o in objs)
        {
            Assert.DoesNotContain(S, o.ToString());
            Assert.DoesNotContain(S, $"{o}");
            Assert.DoesNotContain(S, string.Format("{0}", o));
        }
        var created = new ClientCreatedDto(id, "n", id, true, S);
        Assert.DoesNotContain(S, (created with { Name = "m" }).ToString());
        Assert.DoesNotContain(S, new InvalidOperationException(created.ToString()).ToString());
        // Note: reflection-based serializers (JsonSerializer) still see the property; the DTOs are never logged as objects.
    }

    [Fact]
    public async Task A_failed_create_or_rotate_error_page_and_a_resubmitted_form_never_contain_a_secret_and_the_first_secret_stays_unusable_after_a_second_create_attempt()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("rs") }));
        var name = Unique("rs");
        var first = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" });
        var secret = SecretShape().Match(await first.Content.ReadAsStringAsync()).Value;
        var id = (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items")[0].GetProperty("id").GetGuid();
        await GiveRoleAsync(api, app, id);
        // resubmit: 409, same single client, secret still valid (the failed attempt did not rotate)
        for (var i = 0; i < 3; i++)
        {
            var again = await WebFixture.PostFormAsync(b, "/Clients/Create", new() { ["Name"] = name, ["App"] = app.ToString(), ["IsActive"] = "true" }, "/Clients/Create");
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
            var html = await again.Content.ReadAsStringAsync();
            Assert.DoesNotContain("gks_", html);
            Assert.DoesNotContain(secret, HeadersOf(again));
        }
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(_f, name, secret)).Status);
        Assert.Single((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray());
    }

    // ---- hostile text ----

    [Fact]
    public async Task Hostile_application_and_client_names_are_encoded_on_every_client_page()
    {
        const string Evil = "<img src=x onerror=alert(1)>";
        WebFixture? f = null;
        var app = Guid.NewGuid();
        var client = Guid.NewGuid();
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method != HttpMethod.Get) return null;
            string? json = null;
            var c = $"{{\"id\":\"{client}\",\"name\":\"ok\",\"appId\":\"{app}\",\"isActive\":true,\"createdAt\":\"2026-01-01T00:00:00Z\",\"updatedAt\":\"2026-01-01T00:00:00Z\"}}";
            var a = $"{{\"id\":\"{app}\",\"name\":\"{Evil.Replace("\"", "\\\"")}\",\"createdAt\":\"2026-01-01T00:00:00Z\"}}";
            if (path == "/v1/applications") json = $"{{\"items\":[{a}],\"nextCursor\":null}}";
            else if (path == $"/v1/applications/{app}") json = a;
            else if (path == "/v1/clients") json = $"{{\"items\":[{c}],\"nextCursor\":null}}";
            else if (path == $"/v1/clients/{client}") json = c;
            return json is null ? null : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        foreach (var p in new[] { "/Clients", "/Clients/Create", $"/Clients/Edit/{client}" })
        {
            var html = await b.GetStringAsync(p);
            Assert.DoesNotContain(Evil, html);
            Assert.Contains("&lt;img", html);
        }
    }

    // ---- crafted requests to every page ----

    [Fact]
    public async Task Crafted_posts_and_gets_to_every_page_never_answer_5xx()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("all") }));
        var role = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "r", description = "d" }));
        var (client, _) = await NewClientAsync(api, Unique("all"), app);
        var uname = Unique("all");
        var user = await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = uname, email = uname + "@example.com", displayName = "", kind = "person" }));
        var unknown = Guid.NewGuid();
        var paths = new List<string>
        {
            "/", "/Error", "/Error?code=500", "/Login", "/Applications", "/Applications/Create", $"/Applications/Edit/{app}", $"/Applications/Delete/{app}",
            $"/Applications/{app}/Roles", $"/Applications/{app}/Roles/Create", $"/Applications/{app}/Roles/Edit/{role}", $"/Applications/{app}/Roles/Delete/{role}",
            "/Users", "/Users/Create", $"/Users/Edit/{user}", $"/Users/Delete/{user}", $"/Users/{user}/Roles", $"/Users/{user}/Roles/Add", $"/Users/{user}/Password", $"/Users/{user}/Sessions", $"/Users/{user}/Sessions/RevokeAll",
            $"/Users/{user}/Roles/Remove/{role}", $"/Users/{user}/Sessions/Revoke/{unknown}",
            "/Clients", "/Clients/Create", $"/Clients/Edit/{client}", $"/Clients/Rotate/{client}", $"/Clients/Delete/{client}",
            $"/Clients/Edit/{unknown}", $"/Clients/Rotate/{unknown}", $"/Clients/Delete/{unknown}", "/Clients/Edit/zzz", "/Clients/Nope", "/Clients/_Secret",
        };
        var crafted = new Dictionary<string, string> { ["Name"] = new string('x', 5000), ["App"] = "{}", ["IsActive"] = "maybe", ["OrigIsActive"] = "\0", ["secret"] = "gks_x", ["id"] = "\u0000", ["cursor"] = "%", ["done"] = "<b>" };
        var failures = new List<string>();
        foreach (var path in paths)
        {
            var get = await b.GetAsync(path);
            if ((int)get.StatusCode >= 500) failures.Add($"GET {path} -> {(int)get.StatusCode}");
            // post without a token, with a token from a page of the same kind, with junk fields, and with an empty body
            var noToken = await b.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string>()));
            if ((int)noToken.StatusCode >= 500) failures.Add($"POST(no token) {path} -> {(int)noToken.StatusCode}");
            var withToken = await WebFixture.PostFormAsync(b, path, new(crafted), "/Clients/Create");
            if ((int)withToken.StatusCode >= 500) failures.Add($"POST(junk) {path} -> {(int)withToken.StatusCode}");
            var empty = await WebFixture.PostFormAsync(b, path, new(), "/Clients/Create");
            if ((int)empty.StatusCode >= 500) failures.Add($"POST(empty) {path} -> {(int)empty.StatusCode}");
            var multi = new StringContent("__RequestVerificationToken=" + Uri.EscapeDataString(await WebFixture.TokenAsync(b, "/Clients/Create")) + "&Name=a&Name=b&IsActive=true&IsActive=false&IsActive=x&App=" + app + "&App=" + app, Encoding.UTF8, "application/x-www-form-urlencoded");
            var m = await b.PostAsync(path, multi);
            if ((int)m.StatusCode >= 500) failures.Add($"POST(multi) {path} -> {(int)m.StatusCode}");
            // a wrong content type and a GET-only path with other verbs
            var json = await b.PostAsync(path, new StringContent("{}", Encoding.UTF8, "application/json"));
            if ((int)json.StatusCode >= 500) failures.Add($"POST(json) {path} -> {(int)json.StatusCode}");
            var put = await b.SendAsync(new HttpRequestMessage(HttpMethod.Put, path));
            if ((int)put.StatusCode >= 500) failures.Add($"PUT {path} -> {(int)put.StatusCode}");
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public async Task Crafted_posts_without_a_session_to_clients_never_answer_5xx()
    {
        var anon = _f.Browser();
        foreach (var p in new[] { "/Clients", "/Clients/Create", $"/Clients/Edit/{Guid.NewGuid()}", "/Clients/Edit/zzz", $"/Clients/Rotate/{Guid.NewGuid()}", $"/Clients/Delete/{Guid.NewGuid()}" })
        {
            var r = await anon.PostAsync(p, new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = "x" }));
            Assert.True((int)r.StatusCode < 500, $"{p}: {(int)r.StatusCode}");
            Assert.DoesNotContain("gks_", await r.Content.ReadAsStringAsync());
        }
    }

    // ---- paging, deterministic ----

    [Fact]
    public async Task Paging_walks_every_client_exactly_once_and_the_next_link_is_encoded()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name = Unique("pg") }));
        for (var i = 0; i < 60; i++) await NewClientAsync(api, $"p-{i:D2}", app);
        var seen = new List<string>();
        var url = $"/Clients?app={app}";
        for (var guard = 0; guard < 10 && url is not null; guard++)
        {
            var html = await b.GetStringAsync(url);
            seen.AddRange(Regex.Matches(html, "<td>(p-\\d\\d)</td>").Select(m => m.Groups[1].Value));
            var next = Regex.Match(html, "href=\"(/Clients\\?[^\"]+)\">Next page");
            url = next.Success ? WebUtility.HtmlDecode(next.Groups[1].Value) : null;
        }
        Assert.Equal(60, seen.Count);
        Assert.Equal(60, seen.Distinct().Count());
    }

    [Fact]
    public async Task User_edit_form_with_hidden_false_and_checked_true_also_means_active()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var name = Unique("ue");
        var id = await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "person" }));
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false })).StatusCode);
        var page = await b.GetStringAsync($"/Users/Edit/{id}");
        var orig = Regex.Match(page, "name=\"OrigIsActive\"[^>]*value=\"([^\"]*)\"").Groups[1].Value;
        var token = await WebFixture.TokenAsync(b, $"/Users/Edit/{id}");
        var body = $"__RequestVerificationToken={Uri.EscapeDataString(token)}&Username={name}&Email={name}%40example.com&DisplayName=Changed&Kind=person&Expiry=&OrigIsActive={orig}&IsActive=false&IsActive=true&Version={await WebFixture.VersionOfAsync(b, $"/Users/Edit/{id}")}";
        var saved = await b.PostAsync($"/Users/Edit/{id}", new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        Assert.Equal("Changed", (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{id}")).GetProperty("displayName").GetString());
        Assert.True((await api.GetFromJsonAsync<JsonElement>($"/v1/users/{id}")).GetProperty("isActive").GetBoolean(), "ticking Active on the user edit form must activate the user");
    }
}
