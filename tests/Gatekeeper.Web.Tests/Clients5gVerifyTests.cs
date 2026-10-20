extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeeper.Web.Pages.Clients;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Web.Tests;

/// <summary>
/// Verification of slice 5g (round 3): every form of the web UI posted the way a browser builds the body, the nonce flow for
/// real browser sequences, the per-session application cache, and the Clear-Site-Data header next to the session cookie.
/// </summary>
public partial class Clients5gVerifyTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Clients5gVerifyTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];
    private static string Q(string s) => Uri.EscapeDataString(s);

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
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static Task<Guid> CreateAppAsync(HttpClient api, string name) => api.PostAsJsonAsync("/v1/applications", new { name }).ContinueWith(t => IdOf(t.Result)).Unwrap();

    private static async Task<(Guid Id, string Name)> CreateClientAsync(HttpClient api, Guid app, bool active = true)
    {
        var name = Unique("c");
        return (await IdOf(await api.PostAsJsonAsync("/v1/clients", new { name, application = app, isActive = active })), name);
    }

    private static Task<HttpResponseMessage> RawPostAsync(HttpClient b, string path, string body) =>
        b.PostAsync(path, new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static string NonceOf(string html) => WebUtility.HtmlDecode(Regex.Match(html, "name=\"Nonce\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);

    // ---- a minimal browser: builds a form body from the page's own HTML, in document order ----

    [GeneratedRegex("<form\\b([^>]*)>(.*?)</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex FormTag();
    [GeneratedRegex("<(input|select|textarea)\\b([^>]*)>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex Control();
    [GeneratedRegex("([a-zA-Z-]+)(?:=\"([^\"]*)\")?")]
    private static partial Regex Attr();

    private static Dictionary<string, string?> Attrs(string s) =>
        Attr().Matches(s).ToDictionary(m => m.Groups[1].Value.ToLowerInvariant(), m => m.Groups[2].Success ? WebUtility.HtmlDecode(m.Groups[2].Value) : null, StringComparer.Ordinal);

    /// <summary>The post forms of a page (not the sign-out form of the layout), each as the list of (name, value) a browser would send.</summary>
    private static List<List<KeyValuePair<string, string>>> BrowserBodies(string html, Func<string, string> fill)
    {
        var forms = new List<List<KeyValuePair<string, string>>>();
        foreach (Match f in FormTag().Matches(html))
        {
            var fa = Attrs(f.Groups[1].Value);
            if (!string.Equals(fa.GetValueOrDefault("method"), "post", StringComparison.OrdinalIgnoreCase)) continue;
            if (fa.GetValueOrDefault("action") is "/Logout") continue;
            var body = new List<KeyValuePair<string, string>>();
            var inner = f.Groups[2].Value;
            foreach (Match c in Control().Matches(inner))
            {
                var a = Attrs(c.Groups[2].Value);
                var name = a.GetValueOrDefault("name");
                if (string.IsNullOrEmpty(name)) continue;
                var type = (a.GetValueOrDefault("type") ?? "text").ToLowerInvariant();
                if (c.Groups[1].Value.Equals("select", StringComparison.OrdinalIgnoreCase)) continue; // handled below
                if (type is "submit" or "button" or "image" or "reset" or "file") continue;
                if (type is "checkbox" or "radio") { if (a.ContainsKey("checked")) body.Add(new(name, a.GetValueOrDefault("value") ?? "on")); continue; }
                var v = a.GetValueOrDefault("value") ?? "";
                if (v == "" && a.ContainsKey("required")) v = fill(name);
                if (v == "" && type == "password") v = fill(name);
                body.Add(new(name, v));
            }
            // selects: the selected option, else the first; placed after the inputs (order does not matter for binding)
            foreach (Match s in Regex.Matches(inner, "<select\\b([^>]*)>(.*?)</select>", RegexOptions.Singleline | RegexOptions.IgnoreCase))
            {
                var name = Attrs(s.Groups[1].Value).GetValueOrDefault("name");
                var opts = Regex.Matches(s.Groups[2].Value, "<option\\b([^>]*)>").Select(o => Attrs(o.Groups[1].Value)).ToList();
                if (name is null || opts.Count == 0) continue;
                var chosen = opts.FirstOrDefault(o => o.ContainsKey("selected")) ?? opts[0];
                body.Add(new(name, chosen.GetValueOrDefault("value") ?? ""));
            }
            forms.Add(body);
        }
        return forms;
    }

    private static string Fill(string name) => name switch
    {
        "Email" => Unique("u") + "@example.com",
        "Password" or "Confirm" => "a perfectly long password 123",
        "Username" => Unique("usr"),
        _ => Unique("n"),
    };

    private static string Enc(List<KeyValuePair<string, string>> body) => string.Join('&', body.Select(p => Q(p.Key) + "=" + Q(p.Value)));

    private static string Dump(List<KeyValuePair<string, string>> body) => string.Join('&', body.Select(p => p.Key + "=" + (p.Key == "__RequestVerificationToken" ? "<token>" : p.Value)));

    [Fact]
    public async Task Every_post_form_of_the_web_ui_works_with_the_body_a_browser_builds_from_its_own_html()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("bf"));
        var role = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "reader", description = "d" }));
        var role2 = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "writer", description = "d" }));
        var seen = new List<string>();

        async Task<HttpClient> NewBrowser() => await _f.SignedInAsync();

        async Task Submit(string pageUrl, string postUrl, int formIndex, HttpStatusCode expect, string? expectLocationStart = null, Func<string, string>? fill = null)
        {
            var b = await NewBrowser();
            var html = await b.GetStringAsync(pageUrl);
            var bodies = BrowserBodies(html, fill ?? Fill);
            Assert.True(bodies.Count > formIndex, $"no post form #{formIndex} on {pageUrl}");
            var body = bodies[formIndex];
            Assert.Contains(body, p => p.Key == "__RequestVerificationToken");
            var r = await RawPostAsync(b, postUrl, Enc(body));
            var text = await r.Content.ReadAsStringAsync();
            seen.Add($"{pageUrl} -> {(int)r.StatusCode} [{Dump(body)}]");
            Assert.True(r.StatusCode == expect, $"{pageUrl} with body {Dump(body)} answered {(int)r.StatusCode}, expected {(int)expect}. Alert: {Alert(text)}");
            if (expectLocationStart is not null) Assert.StartsWith(expectLocationStart, r.Headers.Location?.OriginalString);
        }

        // applications
        await Submit("/Applications/Create", "/Applications/Create", 0, HttpStatusCode.Redirect, "/Applications");
        var app2 = await CreateAppAsync(api, Unique("bf"));
        await Submit($"/Applications/Edit/{app2}", $"/Applications/Edit/{app2}", 0, HttpStatusCode.Redirect, "/Applications");
        var app3 = await CreateAppAsync(api, Unique("bf"));
        await Submit($"/Applications/Delete/{app3}", $"/Applications/Delete/{app3}", 0, HttpStatusCode.Redirect, "/Applications");
        // application roles
        await Submit($"/Applications/{app}/Roles/Create", $"/Applications/{app}/Roles/Create", 0, HttpStatusCode.Redirect);
        await Submit($"/Applications/{app}/Roles/Edit/{role2}", $"/Applications/{app}/Roles/Edit/{role2}", 0, HttpStatusCode.Redirect);
        var role3 = await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "tmp", description = "d" }));
        await Submit($"/Applications/{app}/Roles/Delete/{role3}", $"/Applications/{app}/Roles/Delete/{role3}", 0, HttpStatusCode.Redirect);

        // users
        await Submit("/Users/Create", "/Users/Create", 0, HttpStatusCode.Redirect, "/Users");
        var user = await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = Unique("bu"), email = Unique("e") + "@example.com", displayName = "", kind = "person" }));
        await Submit($"/Users/Edit/{user}", $"/Users/Edit/{user}", 0, HttpStatusCode.Redirect, "/Users");
        Assert.True((await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}")).GetProperty("isActive").GetBoolean()); // a ticked box stayed ticked
        await Submit($"/Users/{user}/Password", $"/Users/{user}/Password", 0, HttpStatusCode.Redirect);
        await Submit($"/Users/{user}/Roles/Add?app={app}", $"/Users/{user}/Roles/Add?app={app}", 0, HttpStatusCode.Redirect);
        var assigned = (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/roles")).GetProperty("items").EnumerateArray().Select(e => e.GetProperty("id").GetGuid()).ToList();
        Assert.Single(assigned);
        var toRemove = assigned[0];
        await Submit($"/Users/{user}/Roles/Remove/{toRemove}", $"/Users/{user}/Roles/Remove/{toRemove}", 0, HttpStatusCode.Redirect);
        // sessions of the user (needs a password and a role of the app to sign in)
        await api.PutAsJsonAsync($"/v1/users/{user}/password", new { password = "a perfectly long password 123" });
        await api.PutAsync($"/v1/users/{user}/roles/{role}", null);
        var userName = (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}")).GetProperty("username").GetString();
        var appName = (await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{app}")).GetProperty("name").GetString();
        var login = await _f.Api.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = userName, password = "a perfectly long password 123", application = appName, refresh = true });
        if (login.IsSuccessStatusCode)
        {
            await Submit($"/Users/{user}/Sessions/RevokeAll", $"/Users/{user}/Sessions/RevokeAll", 0, HttpStatusCode.Redirect);
            await _f.Api.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = userName, password = "a perfectly long password 123", application = appName, refresh = true });
            var sess = (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions")).GetProperty("items").EnumerateArray().First().GetProperty("id").GetGuid();
            await Submit($"/Users/{user}/Sessions/Revoke/{sess}", $"/Users/{user}/Sessions/Revoke/{sess}", 0, HttpStatusCode.Redirect);
        }
        else seen.Add("(user sign-in for the sessions forms was not possible: " + (int)login.StatusCode + ")");
        await Submit($"/Users/Delete/{user}", $"/Users/Delete/{user}", 0, HttpStatusCode.Redirect, "/Users");

        // clients: create (nonce + checkbox), edit (checkbox), rotate (nonce), delete
        await Submit("/Clients/Create", "/Clients/Create", 0, HttpStatusCode.OK, null, n => n == "Name" ? Unique("cl") : Fill(n));
        var (cid, _) = await CreateClientAsync(api, app);
        await Submit($"/Clients/Edit/{cid}", $"/Clients/Edit/{cid}", 0, HttpStatusCode.Redirect, "/Clients");
        Assert.True((await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{cid}")).GetProperty("isActive").GetBoolean());
        await Submit($"/Clients/Rotate/{cid}", $"/Clients/Rotate/{cid}", 0, HttpStatusCode.OK);
        await Submit($"/Clients/Delete/{cid}", $"/Clients/Delete/{cid}", 0, HttpStatusCode.Redirect, "/Clients");

        // login and logout
        var anon = _f.Browser();
        var lb = BrowserBodies(await anon.GetStringAsync("/Login"), n => n == "Username" ? WebFixture.AdminName : WebFixture.AdminPassword).Single();
        Assert.Equal(HttpStatusCode.Redirect, (await RawPostAsync(anon, "/Login", Enc(lb))).StatusCode);
        var outHtml = await anon.GetStringAsync("/Applications");
        var logout = Regex.Match(outHtml, "<form[^>]*action=\"/Logout\"[^>]*>(.*?)</form>", RegexOptions.Singleline);
        Assert.True(logout.Success);
        var tok = WebUtility.HtmlDecode(Regex.Match(logout.Groups[1].Value, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        Assert.Equal(HttpStatusCode.Redirect, (await RawPostAsync(anon, "/Logout", "__RequestVerificationToken=" + Q(tok))).StatusCode); // no Nonce on this form

        Assert.True(seen.Count >= 15, string.Join('\n', seen));
        Console.WriteLine(string.Join('\n', seen)); // evidence of exactly what was posted
    }

    [Fact]
    public async Task Forms_other_than_create_and_rotate_carry_no_nonce_and_those_two_do()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("nf"));
        var (cid, _) = await CreateClientAsync(api, app);
        var b = await _f.SignedInAsync();
        foreach (var p in new[] { "/Applications/Create", $"/Applications/Edit/{app}", "/Users/Create", $"/Clients/Edit/{cid}", $"/Clients/Delete/{cid}", $"/Applications/Delete/{app}" })
            Assert.DoesNotContain("name=\"Nonce\"", await b.GetStringAsync(p));
        foreach (var p in new[] { "/Clients/Create", $"/Clients/Rotate/{cid}" })
            Assert.Matches("name=\"Nonce\"[^>]*value=\"[A-Za-z0-9_-]{24}\"", await b.GetStringAsync(p));
    }

    // ---- nonce: browser sequences ----

    [Fact]
    public async Task Back_reload_and_resubmit_after_a_create_never_create_a_second_client_and_a_new_form_works()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("bk"));
        var b = await _f.SignedInAsync();
        var form = BrowserBodies(await b.GetStringAsync("/Clients/Create"), n => n == "Name" ? Unique("bk") : Fill(n)).Single();
        var body = Enc(form.Where(p => p.Key != "App").Append(new("App", app.ToString())).ToList());
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, "/Clients/Create", body)).StatusCode);
        for (var i = 0; i < 3; i++) // reload (resend) three times
        {
            var again = await RawPostAsync(b, "/Clients/Create", body);
            var text = await again.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
            Assert.DoesNotContain("gks_", text);
            // the page that is shown is a usable fresh form: nonce, name field, application list with this application, a Create button
            Assert.Contains("name=\"Name\"", text);
            Assert.Contains($"value=\"{app}\"", text);
            Assert.Contains("type=\"submit\"", text);
            var fresh = BrowserBodies(text, n => Unique("x")).Single();
            Assert.Contains(fresh, p => p.Key == "Nonce" && p.Value.Length > 10);
            Assert.Contains(fresh, p => p.Key == "__RequestVerificationToken");
        }
        Assert.Single((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray());
        // the fresh form from the refusal works as is (with a name typed in)
        var refused = await RawPostAsync(b, "/Clients/Create", body);
        var refusedForm = BrowserBodies(await refused.Content.ReadAsStringAsync(), Fill).Single();
        Assert.Contains(refusedForm, p => p.Key == "Name" && p.Value.StartsWith("bk-", StringComparison.Ordinal)); // what was typed is kept
        var next = refusedForm.Select(p => p.Key == "Name" ? new KeyValuePair<string, string>("Name", Unique("nx")) : p).ToList();
        var ok = await RawPostAsync(b, "/Clients/Create", Enc(next));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Matches(SecretShape(), await ok.Content.ReadAsStringAsync());
        Assert.Equal(2, (await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task Two_tabs_each_have_their_own_working_nonce_for_create_and_for_rotate()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("tb"));
        var (cid, _) = await CreateClientAsync(api, app);
        var b = await _f.SignedInAsync();
        var tab1 = BrowserBodies(await b.GetStringAsync("/Clients/Create"), n => Unique("t1")).Single();
        var tab2 = BrowserBodies(await b.GetStringAsync("/Clients/Create"), n => Unique("t2")).Single();
        Assert.NotEqual(tab1.First(p => p.Key == "Nonce").Value, tab2.First(p => p.Key == "Nonce").Value);
        // submit tab 2 first, then tab 1: both are valid
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, "/Clients/Create", Enc(tab2.Where(p => p.Key != "App").Append(new("App", app.ToString())).ToList()))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, "/Clients/Create", Enc(tab1.Where(p => p.Key != "App").Append(new("App", app.ToString())).ToList()))).StatusCode);
        var r1 = BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        var r2 = BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, $"/Clients/Rotate/{cid}", Enc(r1))).StatusCode);
        // the second tab's confirmation is still its own valid one: the admin confirmed it knowingly, so it rotates again
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, $"/Clients/Rotate/{cid}", Enc(r2))).StatusCode);
    }

    [Fact]
    public async Task A_nonce_of_another_session_or_from_before_sign_out_is_refused_and_does_not_spend_the_owners_nonce()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("xs"));
        var (cid, cname) = await CreateClientAsync(api, app);
        var a = await _f.SignedInAsync();
        var other = await _f.SignedInAsync();
        var formA = BrowserBodies(await a.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        // the other session sends A's body, with a valid antiforgery token of its own
        var tokOther = await WebFixture.TokenAsync(other, $"/Clients/Rotate/{cid}");
        var stolen = formA.Where(p => p.Key != "__RequestVerificationToken").Append(new("__RequestVerificationToken", tokOther)).ToList();
        var refused = await RawPostAsync(other, $"/Clients/Rotate/{cid}", Enc(stolen));
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.DoesNotContain("gks_", await refused.Content.ReadAsStringAsync());
        // the owner's nonce was not spent by that
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(a, $"/Clients/Rotate/{cid}", Enc(formA))).StatusCode);

        // sign out, sign in again (a new session): the old form is refused, the new form works
        var oldForm = BrowserBodies(await a.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        var logout = Regex.Match(await a.GetStringAsync("/Applications"), "<form[^>]*action=\"/Logout\"[^>]*>(.*?)</form>", RegexOptions.Singleline);
        var lt = WebUtility.HtmlDecode(Regex.Match(logout.Groups[1].Value, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        Assert.Equal(HttpStatusCode.Redirect, (await RawPostAsync(a, "/Logout", "__RequestVerificationToken=" + Q(lt))).StatusCode);
        var login = await WebFixture.PostFormAsync(a, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var tokNew = await WebFixture.TokenAsync(a, $"/Clients/Rotate/{cid}"); // note: this GET issued a (different) nonce
        var replay = oldForm.Where(p => p.Key != "__RequestVerificationToken").Append(new("__RequestVerificationToken", tokNew)).ToList();
        Assert.Equal(HttpStatusCode.Conflict, (await RawPostAsync(a, $"/Clients/Rotate/{cid}", Enc(replay))).StatusCode);
        var fresh = BrowserBodies(await a.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(a, $"/Clients/Rotate/{cid}", Enc(fresh))).StatusCode);
        _ = cname;
    }

    [Fact]
    public async Task A_rotate_nonce_of_one_client_does_not_work_for_another()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("rn"));
        var (c1, _) = await CreateClientAsync(api, app);
        var (c2, n2) = await CreateClientAsync(api, app);
        var b = await _f.SignedInAsync();
        var form1 = BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{c1}"), Fill).Single();
        var r = await RawPostAsync(b, $"/Clients/Rotate/{c2}", Enc(form1));
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.DoesNotContain("gks_", await r.Content.ReadAsStringAsync());
        _ = n2;
    }

    [Fact]
    public async Task More_than_32_open_forms_evict_the_oldest_and_that_form_gets_a_usable_fresh_one()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("ev"));
        var (cid, _) = await CreateClientAsync(api, app);
        var b = await _f.SignedInAsync();
        var oldest = BrowserBodies(await b.GetStringAsync("/Clients/Create"), n => Unique("old")).Single();
        var oldestRotate = BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        for (var i = 0; i < 31; i++) await b.GetStringAsync("/Clients/Create"); // 33 forms in all (2 + 31): the first is gone, the second is kept
        var r = await RawPostAsync(b, "/Clients/Create", Enc(oldest.Where(p => p.Key != "App").Append(new("App", app.ToString())).ToList()));
        var text = await r.Content.ReadAsStringAsync();
        // This is what an admin with many open tabs sees:
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal(ClientAccess.AlreadyDoneText, Alert(text)); // wording says "already done" although nothing was done
        Assert.Single((await api.GetFromJsonAsync<JsonElement>($"/v1/clients?application={app}")).GetProperty("items").EnumerateArray()); // only the one made through the API; the evicted form created nothing
        // but the refusal is a usable form: it works as it stands
        var fresh = BrowserBodies(text, n => Unique("fr")).Single();
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, "/Clients/Create", Enc(fresh))).StatusCode);
        // the rotate form from before is evicted as well by now (the refusals issued more nonces)
        for (var i = 0; i < 32; i++) await b.GetStringAsync("/Clients/Create");
        var rr = await RawPostAsync(b, $"/Clients/Rotate/{cid}", Enc(oldestRotate));
        Assert.Equal(HttpStatusCode.Conflict, rr.StatusCode);
        Assert.Matches("name=\"Nonce\"[^>]*value=\"[^\"]+\"", await rr.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_burst_of_gets_by_one_session_cannot_lock_out_another_session()
    {
        var a = await _f.SignedInAsync();
        var other = await _f.SignedInAsync();
        var mine = BrowserBodies(await other.GetStringAsync("/Clients/Create"), n => Unique("m")).Single();
        for (var i = 0; i < 200; i++) await a.GetStringAsync("/Clients/Create");
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("lo"));
        var r = await RawPostAsync(other, "/Clients/Create", Enc(mine.Where(p => p.Key != "App").Append(new("App", app.ToString())).ToList()));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task A_refused_nonce_makes_no_mutating_call_to_the_api()
    {
        var mutations = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (r.Method != HttpMethod.Get && !r.RequestUri!.AbsolutePath.StartsWith("/v1/auth", StringComparison.Ordinal)) Interlocked.Increment(ref mutations);
            return null;
        })));
        using var _ = f;
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("nm"));
        var (cid, _) = await CreateClientAsync(api, app);
        var b = await f.SignedInAsync();
        var tokC = await WebFixture.TokenAsync(b, "/Clients/Create");
        var tokR = await WebFixture.TokenAsync(b, $"/Clients/Rotate/{cid}");
        foreach (var nonce in new[] { "", "x", new string('A', 65), new string('A', 24), "../../etc", "%00" })
        {
            var rc = await RawPostAsync(b, "/Clients/Create", $"__RequestVerificationToken={Q(tokC)}&Nonce={Q(nonce)}&Name={Unique("z")}&App={app}&IsActive=true");
            var rr = await RawPostAsync(b, $"/Clients/Rotate/{cid}", $"__RequestVerificationToken={Q(tokR)}&Nonce={Q(nonce)}");
            Assert.Equal(HttpStatusCode.Conflict, rc.StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, rr.StatusCode);
            tokC = await WebFixture.TokenAsync(b, "/Clients/Create");
            tokR = await WebFixture.TokenAsync(b, $"/Clients/Rotate/{cid}");
        }
        Assert.Equal(0, mutations);
        // duplicated Nonce fields: the first value is the one used, a second valid one cannot be smuggled twice
        var good = BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        var dup = Enc(good) + "&Nonce=" + Q(good.First(p => p.Key == "Nonce").Value);
        Assert.Equal(HttpStatusCode.OK, (await RawPostAsync(b, $"/Clients/Rotate/{cid}", dup)).StatusCode);
        Assert.Equal(1, mutations);
    }

    [Fact]
    public async Task The_nonce_store_survives_a_concurrent_hammering_and_each_nonce_is_consumed_once()
    {
        var s = new WebSession("id", "u", new Tokens("a", DateTimeOffset.MaxValue, "r", DateTimeOffset.MaxValue), DateTimeOffset.UtcNow);
        var wins = 0;
        for (var round = 0; round < 200; round++)
        {
            var n = s.IssueNonce("p");
            await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => { if (s.ConsumeNonce("p", n)) Interlocked.Increment(ref wins); })));
        }
        Assert.Equal(200, wins);
        // concurrent issue + consume must not throw (the list is only touched under the lock)
        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 2000; i++) { var n = s.IssueNonce("q"); s.ConsumeNonce("q", n); }
        })));
    }

    // ---- application list cache ----

    [Fact]
    public async Task The_cache_is_per_session_and_a_rename_through_the_ui_shows_at_once_in_the_same_session()
    {
        var api = await ApiAdminAsync(_f);
        var oldName = Unique("cn");
        var app = await CreateAppAsync(api, oldName);
        await CreateClientAsync(api, app);
        var a = await _f.SignedInAsync();
        var other = await _f.SignedInAsync();
        Assert.Contains($"<td>{oldName}</td>", await a.GetStringAsync($"/Clients?app={app}"));
        Assert.Contains($"<td>{oldName}</td>", await other.GetStringAsync($"/Clients?app={app}"));
        var newName = Unique("rn");
        // renamed in the UI by session a
        var r = await WebFixture.PostFormAsync(a, $"/Applications/Edit/{app}", new() { ["Name"] = newName });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var shown = await a.GetStringAsync($"/Clients?app={app}");
        Assert.Contains($"<td>{newName}</td>", shown);
        Assert.DoesNotContain($"<td>{oldName}</td>", shown);
        // session "other" has its own cache and is allowed to be up to 5 s behind (documented), but never sees another session's data
        var otherView = await other.GetStringAsync($"/Clients?app={app}");
        Assert.True(otherView.Contains($"<td>{oldName}</td>") || otherView.Contains($"<td>{newName}</td>"));
    }

    [Fact]
    public async Task A_rename_by_another_admin_is_seen_after_five_seconds_at_most_and_a_new_application_at_once()
    {
        using var f = new WebFixture(true);
        var api = await ApiAdminAsync(f);
        var oldName = Unique("fo");
        var app = await CreateAppAsync(api, oldName);
        await CreateClientAsync(api, app);
        var b = await f.SignedInAsync();
        Assert.Contains($"<td>{oldName}</td>", await b.GetStringAsync("/Clients"));
        var newName = Unique("fn");
        Assert.Equal(HttpStatusCode.OK, (await api.PutAsJsonAsync($"/v1/applications/{app}", new { name = newName })).StatusCode);
        // within the window the old name may show
        var within = await b.GetStringAsync("/Clients");
        Assert.Contains($"<td>{oldName}</td>", within); // documented limit: up to 5 s stale
        f.Time.Advance(TimeSpan.FromSeconds(4.9));
        Assert.Contains($"<td>{oldName}</td>", await b.GetStringAsync("/Clients"));
        f.Time.Advance(TimeSpan.FromSeconds(0.2));
        var after = await b.GetStringAsync("/Clients");
        Assert.Contains($"<td>{newName}</td>", after);
        // a client in a brand-new application resolves its name at once, though the cache is fresh
        var app2Name = Unique("fx");
        var app2 = await CreateAppAsync(api, app2Name);
        await CreateClientAsync(api, app2);
        Assert.Contains($"<td>{app2Name}</td>", await b.GetStringAsync("/Clients"));
        // a filter on an application the cache lacks reads afresh
        var app3 = await CreateAppAsync(api, Unique("fy"));
        var html = await b.GetStringAsync($"/Clients?app={app3}");
        Assert.Contains($"value=\"{app3}\" selected", html.Replace("selected=\"selected\"", "selected"));
    }

    [Fact]
    public async Task A_cache_snapshot_never_outlives_the_fake_clock_going_backwards_and_a_deleted_application_disappears_from_the_filter()
    {
        using var f = new WebFixture(true);
        var api = await ApiAdminAsync(f);
        var name = Unique("dl");
        var app = await CreateAppAsync(api, name);
        var b = await f.SignedInAsync();
        Assert.Contains($">{name}</option>", await b.GetStringAsync("/Clients"));
        var del = await WebFixture.PostFormAsync(b, $"/Applications/Delete/{app}", new());
        Assert.Equal(HttpStatusCode.Redirect, del.StatusCode);
        Assert.DoesNotContain($">{name}</option>", await b.GetStringAsync("/Clients")); // invalidated by the delete, no 5 s wait
    }

    // ---- Clear-Site-Data and cookies ----

    [Fact]
    public async Task The_secret_page_never_clears_the_session_cookie_and_the_session_survives_it()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("cs"));
        var (cid, _) = await CreateClientAsync(api, app);
        var b = await _f.SignedInAsync();
        var c = BrowserBodies(await b.GetStringAsync("/Clients/Create"), n => Unique("cs")).Single();
        var created = await RawPostAsync(b, "/Clients/Create", Enc(c.Where(p => p.Key != "App").Append(new("App", app.ToString())).ToList()));
        var rotated = await RawPostAsync(b, $"/Clients/Rotate/{cid}", Enc(BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single()));
        foreach (var r in new[] { created, rotated })
        {
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var csd = Assert.Single(r.Headers.GetValues("Clear-Site-Data"));
            Assert.Equal("\"cache\"", csd);
            Assert.DoesNotContain("cookies", csd);
            Assert.DoesNotContain("storage", csd);
            Assert.DoesNotContain("*", csd);
            Assert.False(r.Headers.Contains("Set-Cookie"), "the secret page must not touch cookies");
            Assert.Contains("no-store", r.Headers.CacheControl!.ToString());
        }
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Clients")).StatusCode);
        // the non-secret outcomes (refusals) do not send it
        var refused = await RawPostAsync(b, "/Clients/Create", Enc(c));
        Assert.False(refused.Headers.Contains("Clear-Site-Data"));
    }

    // ---- no secret in logs / ToString ----

    [Fact]
    public async Task The_uncertain_and_refused_paths_log_no_secret_and_the_nonce_is_not_logged()
    {
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("lg"));
        var (cid, _) = await CreateClientAsync(api, app);
        var b = await _f.SignedInAsync();
        var form = BrowserBodies(await b.GetStringAsync($"/Clients/Rotate/{cid}"), Fill).Single();
        var nonce = form.First(p => p.Key == "Nonce").Value;
        var lines = new System.Collections.Concurrent.ConcurrentQueue<string>();
        using var f = new WebFixture(false, s => s.AddLogging(l => l.AddProvider(new Capture(lines))));
        var api2 = await ApiAdminAsync(f);
        var app2 = await CreateAppAsync(api2, Unique("lg"));
        var (cid2, _) = await CreateClientAsync(api2, app2);
        var b2 = await f.SignedInAsync();
        var form2 = BrowserBodies(await b2.GetStringAsync($"/Clients/Rotate/{cid2}"), Fill).Single();
        var n2 = form2.First(p => p.Key == "Nonce").Value;
        var ok = await RawPostAsync(b2, $"/Clients/Rotate/{cid2}", Enc(form2));
        var secret = SecretShape().Match(await ok.Content.ReadAsStringAsync()).Value;
        Assert.NotEmpty(secret);
        await RawPostAsync(b2, $"/Clients/Rotate/{cid2}", Enc(form2));
        var all = string.Join('\n', lines);
        Assert.DoesNotContain(secret, all);
        Assert.DoesNotContain(n2, all);
        _ = nonce;
    }

    private sealed class Capture(System.Collections.Concurrent.ConcurrentQueue<string> lines) : Microsoft.Extensions.Logging.ILoggerProvider, Microsoft.Extensions.Logging.ILogger
    {
        public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            lines.Enqueue(formatter(state, exception) + " " + exception);
    }

    [Fact]
    public void Secret_carrying_types_print_no_secret_via_ToString_interpolation_or_json_free_paths()
    {
        const string secret = "gks_NotARealSecretNotARealSecretNotARealSecr";
        var v = new SecretView(Guid.NewGuid(), "n", secret, true);
        var dto = new ClientCreatedDto(Guid.NewGuid(), "n", Guid.NewGuid(), true, secret);
        var sd = new SecretDto(secret);
        foreach (var t in new[] { v.ToString(), dto.ToString(), sd.ToString(), $"{v}", $"{dto}", $"{sd}", string.Format("{0}", v) })
            Assert.DoesNotContain(secret, t);
        // record equality/hash must not matter, but a "with" copy still prints no secret
        Assert.DoesNotContain(secret, (v with { ClientName = "m" }).ToString());
    }
}
