extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent QA of slice 6e, written from the spec: hidden Version on every form, duplicates, double submit, cache, 404, other flows.</summary>
public class Versions6eQaTests : IClassFixture<WebFixture>
{
    private const string Changed = "Changed by someone else since you opened it. The current values are shown; apply your change again.";
    private const string Missing = "The form is out of date or incomplete. The current values are shown; apply your change again.";
    private readonly WebFixture _f;

    public Versions6eQaTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<HttpClient> ApiAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private static async Task<Guid> CreateAsync(HttpClient api, string path, object body)
    {
        var r = await api.PostAsJsonAsync(path, body);
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<JsonElement> GetAsync(HttpClient api, string path) => await api.GetFromJsonAsync<JsonElement>(path);

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value.Trim();

    private static List<KeyValuePair<string, string>> Hidden(string html)
    {
        var main = html[Math.Max(0, html.IndexOf("<main", StringComparison.Ordinal))..];
        return Regex.Matches(main, "<input[^>]*type=\"hidden\"[^>]*>").Select(m => new KeyValuePair<string, string>(
            Regex.Match(m.Value, "name=\"([^\"]*)\"").Groups[1].Value,
            WebUtility.HtmlDecode(Regex.Match(m.Value, "value=\"([^\"]*)\"").Groups[1].Value))).ToList();
    }

    private static Task<HttpResponseMessage> Post(HttpClient b, string path, IEnumerable<KeyValuePair<string, string>> form) =>
        b.PostAsync(path, new FormUrlEncodedContent(form));

    private static List<KeyValuePair<string, string>> Without(List<KeyValuePair<string, string>> f, string name)
    {
        f.RemoveAll(p => p.Key == name);
        return f;
    }

    private static List<KeyValuePair<string, string>> Set(List<KeyValuePair<string, string>> f, string name, string value)
    {
        Without(f, name);
        f.Add(new(name, value));
        return f;
    }

    // ---- real duplicate fields (Version=1&Version=1), not a comma inside one value ---------------------------------

    [Theory]
    [InlineData("Applications")]
    [InlineData("Clients")]
    [InlineData("Users")]
    [InlineData("Roles")]
    public async Task A_version_sent_twice_is_refused_and_nothing_is_deleted(string kind)
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        string path, resource;
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        switch (kind)
        {
            case "Applications": path = $"/Applications/Delete/{app}"; resource = $"/v1/applications/{app}"; break;
            case "Clients":
                var c = await CreateAsync(api, "/v1/clients", new { name = Unique("c"), application = app, isActive = true });
                path = $"/Clients/Delete/{c}"; resource = $"/v1/clients/{c}"; break;
            case "Users":
                var n = Unique("u");
                var u = await CreateAsync(api, "/v1/users", new { username = n, email = n + "@example.com", displayName = "", kind = "person" });
                path = $"/Users/Delete/{u}"; resource = $"/v1/users/{u}"; break;
            default:
                var r = await CreateAsync(api, $"/v1/applications/{app}/roles", new { name = Unique("r"), description = "" });
                path = $"/Applications/{app}/Roles/Delete/{r}"; resource = $"/v1/roles/{r}"; break;
        }
        var form = Hidden(await b.GetStringAsync(path));
        var v = form.First(p => p.Key == "Version").Value;
        Without(form, "Version");
        form.Add(new("Version", "999999")); // wrong first, right second
        form.Add(new("Version", v));
        var resp = await Post(b, path, form);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Equal(Missing, Alert(await resp.Content.ReadAsStringAsync()));
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync(resource)).StatusCode);
    }

    [Fact]
    public async Task Odd_but_digit_like_versions_never_delete()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var path = $"/Applications/Delete/{app}";
        foreach (var bad in new[] { "١", "１", "+1", "-0", "1\n", "1\0", "9223372036854775808", "0000000000000000001x", "%31", "\t1" })
        {
            var form = Set(Hidden(await b.GetStringAsync(path)), "Version", bad);
            var resp = await Post(b, path, form);
            Assert.True(resp.StatusCode is HttpStatusCode.BadRequest, $"'{bad}' -> {(int)resp.StatusCode}");
            Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/v1/applications/{app}")).StatusCode);
        }
    }

    [Fact]
    public async Task Without_the_antiforgery_token_a_valid_version_still_writes_nothing()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var path = $"/Applications/Delete/{app}";
        var form = Without(Hidden(await b.GetStringAsync(path)), "__RequestVerificationToken");
        var resp = await Post(b, path, form);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/v1/applications/{app}")).StatusCode);
    }

    // ---- double submit ------------------------------------------------------------------------------------------

    [Fact]
    public async Task Submitting_the_same_edit_form_twice_saves_once_and_the_second_is_a_412()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var role = await CreateAsync(api, $"/v1/applications/{app}/roles", new { name = Unique("r"), description = "d" });
        var path = $"/Applications/{app}/Roles/Edit/{role}";
        var form = Set(Set(Hidden(await b.GetStringAsync(path)), "Name", Unique("n")), "Description", "once");
        var first = await Post(b, path, form);
        var second = await Post(b, path, form);
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, second.StatusCode);
        Assert.Equal(Changed, Alert(await second.Content.ReadAsStringAsync()));
        Assert.Equal(2, (await GetAsync(api, $"/v1/roles/{role}")).GetProperty("version").GetInt64());
    }

    [Fact]
    public async Task Submitting_the_same_delete_form_twice_deletes_once_then_404()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var c = await CreateAsync(api, "/v1/clients", new { name = Unique("c"), application = app, isActive = true });
        var path = $"/Clients/Delete/{c}";
        var form = Hidden(await b.GetStringAsync(path));
        Assert.Equal(HttpStatusCode.Redirect, (await Post(b, path, form)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(b, path, form)).StatusCode);
    }

    // ---- 404 comes first ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/Users/Edit/{0}")]
    [InlineData("/Users/Delete/{0}")]
    [InlineData("/Clients/Edit/{0}")]
    [InlineData("/Clients/Delete/{0}")]
    [InlineData("/Applications/Edit/{0}")]
    [InlineData("/Applications/Delete/{0}")]
    public async Task An_unknown_resource_is_404_with_good_or_garbage_version(string template)
    {
        var b = await _f.SignedInAsync();
        var path = string.Format(template, Guid.NewGuid());
        var (token, _) = await WebFixture.TokenAndNonceAsync(b, "/Applications/Create");
        foreach (var v in new[] { "1", "abc", "" })
        {
            var resp = await Post(b, path, [new("__RequestVerificationToken", token), new("Version", v), new("Name", "x")]);
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
    }

    // ---- application list cache is invalidated also on a 412 ---------------------------------------------------

    [Fact]
    public async Task A_refused_stale_rename_still_drops_the_cached_application_names()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("old") });
        var cname = Unique("c");
        await CreateAsync(api, "/v1/clients", new { name = cname, application = app, isActive = true });
        var old = (await GetAsync(api, $"/v1/applications/{app}")).GetProperty("name").GetString()!;
        var list = await b.GetStringAsync("/Clients"); // fills the per-session cache
        Assert.Contains(old, list);

        var path = $"/Applications/Edit/{app}";
        var form = Hidden(await b.GetStringAsync(path));
        var theirs = Unique("theirs");
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/applications/{app}", new { name = theirs })).StatusCode);
        var resp = await Post(b, path, Set(form, "Name", Unique("mine")));
        Assert.Equal(HttpStatusCode.PreconditionFailed, resp.StatusCode);

        var after = await b.GetStringAsync("/Clients"); // no clock advance: only invalidation can refresh it
        Assert.Contains(theirs, after);
        Assert.DoesNotContain(old, after);
    }

    // ---- concurrent edit + delete, the same form twice at once ---------------------------------------------------

    [Fact]
    public async Task Concurrent_edit_and_delete_of_an_application_from_one_version_leave_one_outcome()
    {
        var api = await ApiAsync();
        var b1 = await _f.SignedInAsync();
        var b2 = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var edit = Set(Hidden(await b1.GetStringAsync($"/Applications/Edit/{app}")), "Name", Unique("renamed"));
        var del = Hidden(await b2.GetStringAsync($"/Applications/Delete/{app}"));
        var rs = await Task.WhenAll(Post(b1, $"/Applications/Edit/{app}", edit), Post(b2, $"/Applications/Delete/{app}", del));
        Assert.All(rs, r => Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.PreconditionFailed or HttpStatusCode.NotFound, r.StatusCode.ToString()));
        Assert.Contains(rs, r => r.StatusCode == HttpStatusCode.Redirect);
        // exactly one of them can have won from the same version
        Assert.Equal(1, rs.Count(r => r.StatusCode == HttpStatusCode.Redirect));
    }

    // ---- a refusal that is not a 412 keeps the posted version (the guard is not reset by a validation error) ----

    [Fact]
    public async Task A_name_conflict_on_rename_keeps_the_posted_version_in_the_form()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var other = Unique("taken");
        await CreateAsync(api, "/v1/applications", new { name = other });
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var path = $"/Applications/Edit/{app}";
        var form = Set(Hidden(await b.GetStringAsync(path)), "Name", other);
        var resp = await Post(b, path, form);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode); // existing behaviour: the page shows the API text
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Equal(form.First(p => p.Key == "Version").Value, Hidden(html).First(p => p.Key == "Version").Value);
    }

    // ---- reserved application: version check first, then the API's 409 ---------------------------------------------

    [Fact]
    public async Task Editing_a_reserved_role_with_a_good_version_is_the_409_and_with_a_bad_one_the_400()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var apps = await GetAsync(api, "/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var role = (await GetAsync(api, $"/v1/applications/{gk}/roles")).GetProperty("items").EnumerateArray().First().GetProperty("id").GetGuid();
        var path = $"/Applications/{gk}/Roles/Delete/{role}";
        var token = await WebFixture.TokenAsync(b, "/Applications"); // the reserved role has no delete form: a crafted post
        var form = new List<KeyValuePair<string, string>> { new("__RequestVerificationToken", token), new("Version", "1") };
        var ok = await Post(b, path, form);
        Assert.Equal(HttpStatusCode.Conflict, ok.StatusCode);
        var bad = await Post(b, path, Set(form, "Version", "x"));
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/v1/roles/{role}")).StatusCode);
    }

    // ---- self-delete on a fresh form ends the session only on success ------------------------------------------

    [Fact]
    public async Task Deleting_oneself_on_a_fresh_confirmation_ends_the_session()
    {
        var api = await ApiAsync();
        var name = Unique("adm");
        var id = await CreateAsync(api, "/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "person" });
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "a long enough password" })).StatusCode);
        var apps = await GetAsync(api, "/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var adminRole = (await GetAsync(api, $"/v1/applications/{gk}/roles")).GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null)).StatusCode);
        var b = _f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = "a long enough password" })).StatusCode);
        var path = $"/Users/Delete/{id}";
        var resp = await Post(b, path, Hidden(await b.GetStringAsync(path)));
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("/Login?ended=1", resp.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.NotFound, (await api.GetAsync($"/v1/users/{id}")).StatusCode);
    }

    // ---- flows without a version still work ----------------------------------------------------------------------

    [Fact]
    public async Task Pages_without_a_version_still_load_and_work()
    {
        var api = await ApiAsync();
        var b = await _f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var role = await CreateAsync(api, $"/v1/applications/{app}/roles", new { name = Unique("r"), description = "" });
        var n = Unique("u");
        var user = await CreateAsync(api, "/v1/users", new { username = n, email = n + "@example.com", displayName = "", kind = "person" });
        var client = await CreateAsync(api, "/v1/clients", new { name = Unique("c"), application = app, isActive = true });

        foreach (var p in new[] { $"/Users/{user}/Roles", $"/Users/{user}/Password", $"/Users/{user}/Sessions", $"/Clients/{client}/Roles", $"/Clients/Rotate/{client}",
                     "/Clients/Create", "/Applications/Create", $"/Applications/{app}/Roles", $"/Applications/{app}/Roles/Create", "/Users/Create" })
        {
            var r = await b.GetAsync(p);
            Assert.True(r.StatusCode == HttpStatusCode.OK, $"{p} -> {(int)r.StatusCode}");
        }

        // Create posts carry no version
        var rc = await WebFixture.PostFormAsync(b, $"/Applications/{app}/Roles/Create", new() { ["Name"] = Unique("r2") });
        Assert.Equal(HttpStatusCode.Redirect, rc.StatusCode);
        var ac = await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = Unique("a2") });
        Assert.Equal(HttpStatusCode.Redirect, ac.StatusCode);
        // user role assignment and password do not need a version (and do not bump it)
        var before = (await GetAsync(api, $"/v1/users/{user}")).GetProperty("version").GetInt64();
        var pw = await WebFixture.PostFormAsync(b, $"/Users/{user}/Password", new() { ["Password"] = "a long enough password", ["Confirm"] = "a long enough password" });
        Assert.True(pw.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK, pw.StatusCode.ToString());
        Assert.Equal(before, (await GetAsync(api, $"/v1/users/{user}")).GetProperty("version").GetInt64());
        _ = role;
    }
}
