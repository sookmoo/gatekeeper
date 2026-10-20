extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent verification of slice 5h (a client's roles), written from the status.md spec.</summary>
public class Clients5hQaTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Clients5hQaTests(WebFixture f) => _f = f;

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

    private static Task<Guid> App(HttpClient api, string n) => api.PostAsJsonAsync("/v1/applications", new { name = n }).ContinueWith(t => IdOf(t.Result)).Unwrap();
    private static Task<Guid> Role(HttpClient api, Guid app, string n) => api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = n, description = "d" }).ContinueWith(t => IdOf(t.Result)).Unwrap();
    private static Task<Guid> Client(HttpClient api, string n, Guid app) => api.PostAsJsonAsync("/v1/clients", new { name = n, application = app, isActive = true }).ContinueWith(t => IdOf(t.Result)).Unwrap();

    private static async Task<HashSet<Guid>> Held(HttpClient api, Guid client)
    {
        var set = new HashSet<Guid>();
        string? cursor = null;
        do
        {
            var j = await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{client}/roles?limit=200" + (cursor is null ? "" : "&cursor=" + Uri.EscapeDataString(cursor)));
            foreach (var r in j.GetProperty("items").EnumerateArray()) set.Add(r.GetProperty("id").GetGuid());
            cursor = j.GetProperty("nextCursor").GetString();
        } while (cursor is not null);
        return set;
    }

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;
    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
    private static HashSet<Guid> Options(string html) => Regex.Matches(html, "<option value=\"([0-9a-f-]{36})\"").Select(m => Guid.Parse(m.Groups[1].Value)).ToHashSet();

    [Fact]
    public async Task Anonymous_posts_and_bad_routes_are_refused_not_500()
    {
        var anon = _f.Browser();
        var cid = Guid.NewGuid();
        foreach (var p in new[] { $"/Clients/{cid}/Roles", $"/Clients/{cid}/Roles/Add", $"/Clients/{cid}/Roles/Remove/{Guid.NewGuid()}" })
        {
            var r = await anon.PostAsync(p, new FormUrlEncodedContent(new Dictionary<string, string>()));
            Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.BadRequest, p + " -> " + r.StatusCode);
            Assert.NotEqual(HttpStatusCode.OK, r.StatusCode);
        }
        var b = await _f.SignedInAsync();
        foreach (var p in new[] { "/Clients/xyz/Roles", "/Clients/xyz/Roles/Add", $"/Clients/{cid}/Roles/Remove/notaguid", $"/Clients/{cid}/Roles/Remove", $"/Clients/{Guid.Empty}/Roles", "/Clients//Roles" })
            Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(p)).StatusCode);
        // PUT/DELETE/other verbs on the pages are not pages
        var del = await b.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/Clients/{cid}/Roles"));
        Assert.True((int)del.StatusCode is 400 or 404 or 405, del.StatusCode.ToString());
    }

    [Fact]
    public async Task More_than_100_roles_in_the_app_page_through_Add_and_a_role_on_page_two_can_be_added()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("big"));
        var client = await Client(api, Unique("bigc"), app);
        var all = new List<Guid>();
        for (var i = 0; i < 105; i++) all.Add(await Role(api, app, $"role{i:000}"));
        var page1 = await b.GetStringAsync($"/Clients/{client}/Roles/Add");
        var o1 = Options(page1);
        Assert.Equal(100, o1.Count);
        var more = Regex.Match(page1, "href=\"(/Clients/[^\"]*Roles/Add\\?cursor=[^\"]+)\"");
        Assert.True(more.Success, "no More link");
        var o2 = Options(await b.GetStringAsync(WebUtility.HtmlDecode(more.Groups[1].Value)));
        Assert.Equal(5, o2.Count);
        Assert.Empty(o1.Intersect(o2));
        Assert.Equal(all.ToHashSet(), o1.Union(o2).ToHashSet());
        var r = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = o2.First().ToString() });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal([o2.First()], await Held(api, client));
    }

    [Fact]
    public async Task A_client_holding_more_than_200_roles_is_handled_by_Add_Remove_and_the_list()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("huge"));
        var client = await Client(api, Unique("hugec"), app);
        var roles = new List<Guid>();
        for (var i = 0; i < 205; i++)
        {
            var id = await Role(api, app, $"h{i:000}");
            roles.Add(id);
            Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/clients/{client}/roles/{id}", null)).StatusCode);
        }
        // every role held: nothing to choose, no select (first page of 100 all held)
        var add = await b.GetStringAsync($"/Clients/{client}/Roles/Add");
        Assert.Empty(Options(add));
        Assert.Contains("No roles to choose from.", add);
        // list pages of 25: walk them all
        var seen = new HashSet<Guid>();
        var path = $"/Clients/{client}/Roles";
        for (var guard = 0; guard < 20; guard++)
        {
            var html = await b.GetStringAsync(path);
            foreach (Match m in Regex.Matches(html, "/Roles/Remove/([0-9a-f-]{36})")) Assert.True(seen.Add(Guid.Parse(m.Groups[1].Value)));
            var next = Regex.Match(html, "href=\"([^\"]*cursor=[^\"]+)\">Next page");
            if (!next.Success) break;
            path = WebUtility.HtmlDecode(next.Groups[1].Value);
        }
        Assert.Equal(roles.ToHashSet(), seen);
        // the last role is beyond the first 200 held: Remove must still find it
        var last = roles.Last();
        var held = await Held(api, client);
        Assert.Equal(205, held.Count);
        foreach (var id in new[] { roles[0], last })
        {
            Assert.Equal(HttpStatusCode.OK, (await b.GetAsync($"/Clients/{client}/Roles/Remove/{id}")).StatusCode);
            var rm = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Remove/{id}", new());
            Assert.Equal(HttpStatusCode.Redirect, rm.StatusCode);
        }
        Assert.Equal(203, (await Held(api, client)).Count);
    }

    [Fact]
    public async Task Role_deleted_between_form_and_post_is_a_404_not_a_crash_and_nothing_is_held()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("del"));
        var client = await Client(api, Unique("delc"), app);
        var role = await Role(api, app, "gone");
        var (token, _) = await WebFixture.TokenAndNonceAsync(b, $"/Clients/{client}/Roles/Add");
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/roles/{role}")).StatusCode);
        var r = await b.PostAsync($"/Clients/{client}/Roles/Add", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token, ["RoleId"] = role.ToString() }));
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        Assert.Empty(await Held(api, client));
    }

    [Fact]
    public async Task Client_deleted_between_form_and_post_is_a_404()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("cdel"));
        var client = await Client(api, Unique("cdelc"), app);
        var role = await Role(api, app, "r");
        var (token, _) = await WebFixture.TokenAndNonceAsync(b, $"/Clients/{client}/Roles/Add");
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/clients/{client}")).StatusCode);
        var r = await b.PostAsync($"/Clients/{client}/Roles/Add", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token, ["RoleId"] = role.ToString() }));
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
    }

    [Fact]
    public async Task Role_removed_by_someone_else_between_confirmation_and_post_is_a_404()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("race"));
        var client = await Client(api, Unique("racec"), app);
        var role = await Role(api, app, "r");
        await api.PutAsync($"/v1/clients/{client}/roles/{role}", null);
        var (token, _) = await WebFixture.TokenAndNonceAsync(b, $"/Clients/{client}/Roles/Remove/{role}");
        await api.DeleteAsync($"/v1/clients/{client}/roles/{role}");
        var r = await b.PostAsync($"/Clients/{client}/Roles/Remove/{role}", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
    }

    [Fact]
    public async Task Adding_a_role_already_held_does_not_duplicate_and_ends_in_a_normal_redirect()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("dup"));
        var client = await Client(api, Unique("dupc"), app);
        var role = await Role(api, app, "r");
        await api.PutAsync($"/v1/clients/{client}/roles/{role}", null);
        var r = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = role.ToString() }, $"/Clients/{client}/Roles");
        Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Conflict, r.StatusCode.ToString());
        Assert.Equal([role], await Held(api, client));
    }

    [Fact]
    public async Task Browser_body_extras_cursor_and_repeated_RoleId_and_query_string_RoleId_are_harmless()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("body"));
        var client = await Client(api, Unique("bodyc"), app);
        var r1 = await Role(api, app, "a");
        var r2 = await Role(api, app, "b");
        // a hostile Cursor in the form body, plus a submit button value
        var resp = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = r1.ToString(), ["Cursor"] = "%%%garbage", ["x"] = "y" });
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        // RoleId only in the query string is not read (it is FromForm)
        var (token, _) = await WebFixture.TokenAndNonceAsync(b, $"/Clients/{client}/Roles/Add");
        var q = await b.PostAsync($"/Clients/{client}/Roles/Add?RoleId={r2}", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));
        Assert.Equal(HttpStatusCode.BadRequest, q.StatusCode);
        Assert.Equal([r1], await Held(api, client));
        // empty RoleId (select with no option selected is not sent; an empty value might be)
        var e = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = "" });
        Assert.Equal(HttpStatusCode.BadRequest, e.StatusCode);
        Assert.Equal("Choose a role.", Alert(await e.Content.ReadAsStringAsync()));
        // Guid.Empty
        var z = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = Guid.Empty.ToString() });
        Assert.True((int)z.StatusCode is 404 or 400, z.StatusCode.ToString());
    }

    [Fact]
    public async Task Bad_cursors_fall_back_to_the_first_page()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("cur"));
        var client = await Client(api, Unique("curc"), app);
        var role = await Role(api, app, "r");
        await api.PutAsync($"/v1/clients/{client}/roles/{role}", null);
        var list = await b.GetAsync($"/Clients/{client}/Roles?cursor=%3Cscript%3E");
        Assert.Equal(HttpStatusCode.Redirect, list.StatusCode);
        Assert.Equal($"/Clients/{client}/Roles", list.Headers.Location?.OriginalString);
        var add = await b.GetAsync($"/Clients/{client}/Roles/Add?cursor=%3Cscript%3E");
        Assert.Equal(HttpStatusCode.OK, add.StatusCode);
        // empty cursor value
        Assert.True((int)(await b.GetAsync($"/Clients/{client}/Roles?cursor=")).StatusCode is 200 or 302);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync($"/Clients/{client}/Roles/Add?cursor=")).StatusCode);
    }

    [Fact]
    public async Task Role_and_description_names_with_markup_characters_are_encoded_end_to_end()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("enc"));
        var client = await Client(api, Unique("encc"), app);
        var resp = await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "a<b>&\"'", description = "<img src=x onerror=1>" });
        if (resp.StatusCode != HttpStatusCode.Created) return; // the API refuses such names: nothing to render
        var role = await IdOf(resp);
        Assert.DoesNotContain("<img src=x", await b.GetStringAsync($"/Clients/{client}/Roles/Add"));
        await api.PutAsync($"/v1/clients/{client}/roles/{role}", null);
        foreach (var p in new[] { $"/Clients/{client}/Roles", $"/Clients/{client}/Roles/Remove/{role}" })
        {
            var html = await b.GetStringAsync(p);
            Assert.DoesNotContain("<img src=x", html);
            Assert.DoesNotContain("a<b>", html);
        }
    }

    [Theory]
    [InlineData(400, "The role could not be changed.")]
    [InlineData(409, "The role could not be changed because of a conflict.")]
    [InlineData(422, "The role could not be changed.")]
    public async Task Refusals_on_PUT_and_DELETE_map_to_fixed_texts_with_the_same_status(int status, string text)
    {
        var rolesSeen = new HashSet<Guid>();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            (r.Method == HttpMethod.Put || r.Method == HttpMethod.Delete) && r.RequestUri!.AbsolutePath.Contains("/clients/") && r.RequestUri.AbsolutePath.Contains("/roles/")
                ? new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent("{\"detail\":\"leak <b>x</b>\"}", System.Text.Encoding.UTF8, "application/json") }
                : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await App(api, Unique("map"));
        var client = await Client(api, Unique("mapc"), app);
        var role = await Role(api, app, "r");
        // hold it for real (bypass the stub with a direct repository-free path: the stub intercepts only the web's calls)
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/clients/{client}/roles/{role}", null)).StatusCode);
        var add = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = role.ToString() }, $"/Clients/{client}/Roles/Remove/{role}");
        Assert.Equal((HttpStatusCode)status, add.StatusCode);
        var html = await add.Content.ReadAsStringAsync();
        Assert.Equal(text, Alert(html));
        Assert.DoesNotContain("leak", html);
        var rm = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Remove/{role}", new());
        Assert.Equal((HttpStatusCode)status, rm.StatusCode);
        html = await rm.Content.ReadAsStringAsync();
        Assert.Equal(text, Alert(html));
        Assert.DoesNotContain("leak", html);
        Assert.Contains(role, await Held(api, client));
    }

    [Theory]
    [InlineData(403)]
    [InlineData(429)]
    public async Task Forbidden_and_throttled_answers_are_honest_and_leak_nothing(int status)
    {
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            r.Method == HttpMethod.Put && r.RequestUri!.AbsolutePath.Contains("/roles/")
                ? new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent("{\"detail\":\"leak\"}", System.Text.Encoding.UTF8, "application/json") }
                : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await App(api, Unique("fb"));
        var client = await Client(api, Unique("fbc"), app);
        var role = await Role(api, app, "r");
        var r = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = role.ToString() }, $"/Clients/{client}/Roles/Add");
        Assert.Equal((HttpStatusCode)status, r.StatusCode);
        Assert.DoesNotContain("leak", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Reserved_client_can_still_have_roles_removed_and_nothing_is_added()
    {
        var clientId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var gk = Guid.Empty;
        var deletes = 0;
        var puts = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (path.StartsWith($"/v1/clients/{clientId}/roles/"))
            {
                if (r.Method == HttpMethod.Put)
                {
                    puts++;
                    return new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("{\"detail\":\"Application 'gatekeeper' is reserved: its service identities cannot hold roles.\"}", System.Text.Encoding.UTF8, "application/json") };
                }
                if (r.Method == HttpMethod.Delete) deletes++;
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            if (path == $"/v1/clients/{clientId}") return Json($"{{\"id\":\"{clientId}\",\"name\":\"legacy\",\"appId\":\"{gk}\",\"isActive\":true,\"createdAt\":\"2026-01-01T00:00:00Z\",\"updatedAt\":\"2026-01-01T00:00:00Z\"}}");
            if (path == $"/v1/clients/{clientId}/roles") return Json($"{{\"items\":[{{\"id\":\"{roleId}\",\"appId\":\"{gk}\",\"name\":\"admin\",\"description\":\"d\"}}],\"nextCursor\":null}}");
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var apps = (await (await ApiAdminAsync(f)).GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray().ToList();
        gk = apps.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var list = await b.GetStringAsync($"/Clients/{clientId}/Roles");
        Assert.Contains($"/Roles/Remove/{roleId}", list);
        Assert.DoesNotContain("/Roles/Add", list);
        var rm = await WebFixture.PostFormAsync(b, $"/Clients/{clientId}/Roles/Remove/{roleId}", new());
        Assert.Equal(HttpStatusCode.Redirect, rm.StatusCode);
        Assert.Equal(1, deletes);
        // a crafted Add with no role / bad role: 400, nothing sent; with a role id: forwarded, the API's 409 shown as fixed text
        foreach (var fields in new[] { new Dictionary<string, string>(), new() { ["RoleId"] = "nope" } })
        {
            var r = await WebFixture.PostFormAsync(b, $"/Clients/{clientId}/Roles/Add", fields, $"/Clients/{clientId}/Roles/Add");
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }
        Assert.Equal(0, puts);
        var forced = await WebFixture.PostFormAsync(b, $"/Clients/{clientId}/Roles/Add", new() { ["RoleId"] = roleId.ToString() }, $"/Clients/{clientId}/Roles/Add");
        Assert.Equal(HttpStatusCode.Conflict, forced.StatusCode);
        Assert.Contains("Clients of the reserved application cannot hold roles.", await forced.Content.ReadAsStringAsync());
        Assert.DoesNotContain("service identities", await forced.Content.ReadAsStringAsync());
        Assert.Equal(1, puts);
    }

    [Fact]
    public async Task Calling_the_page_twice_in_parallel_is_safe()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await App(api, Unique("par"));
        var client = await Client(api, Unique("parc"), app);
        var role = await Role(api, app, "r");
        var (token, _) = await WebFixture.TokenAndNonceAsync(b, $"/Clients/{client}/Roles/Add");
        Task<HttpResponseMessage> Post() => b.PostAsync($"/Clients/{client}/Roles/Add", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token, ["RoleId"] = role.ToString() }));
        var rs = await Task.WhenAll(Post(), Post(), Post());
        Assert.All(rs, r => Assert.True((int)r.StatusCode < 500, r.StatusCode.ToString()));
        Assert.Equal([role], await Held(api, client));
    }
}
