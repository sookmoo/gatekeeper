extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent verification of slice 5c, written from the status.md spec.</summary>
public class Roles5cExtraTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Roles5cExtraTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<string> CreateAppAsync(HttpClient b, string name)
    {
        var r = await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = name });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var list = await b.GetStringAsync("/Applications");
        return Regex.Match(list, $"<td>{name}</td>\\s*<td><code>([0-9a-f-]{{36}})</code>").Groups[1].Value;
    }

    private static string RoleId(string html, string name) =>
        Regex.Match(html, $"<td>{Regex.Escape(name)}</td>\\s*<td>[^<]*</td>\\s*<td>\\s*<a href=\"/Applications/[0-9a-f-]{{36}}/Roles/Edit/([0-9a-f-]{{36}})\"").Groups[1].Value;

    private async Task<HttpClient> ApiAdminAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    [Fact]
    public async Task Paging_follows_the_cursor_across_pages_without_repeats_and_survives_a_bad_cursor()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("pg"));
        var api = await ApiAdminAsync();
        for (var i = 0; i < 27; i++)
            Assert.Equal(HttpStatusCode.Created, (await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = $"r{i:00}", description = "" })).StatusCode);

        var path = $"/Applications/{app}/Roles";
        var first = await b.GetStringAsync(path);
        Assert.Equal(25, Regex.Matches(first, "<td>r\\d\\d</td>").Count);
        var next = Regex.Match(first, "href=\"([^\"]*cursor=[^\"]*)\">Next page").Groups[1].Value;
        Assert.NotEmpty(next);
        var second = await b.GetStringAsync(System.Net.WebUtility.HtmlDecode(next));
        var names = Regex.Matches(second, "<td>(r\\d\\d)</td>").Select(m => m.Groups[1].Value).ToList();
        Assert.Equal(new[] { "r25", "r26" }, names);
        Assert.DoesNotContain("Next page", second);

        foreach (var bad in new[] { "garbage", "!!!", new string('a', 100), "" })
        {
            var r = await b.GetAsync($"{path}?cursor={Uri.EscapeDataString(bad)}");
            Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK, $"cursor '{bad}' -> {r.StatusCode}");
            if (r.StatusCode == HttpStatusCode.Redirect) Assert.Equal(path, r.Headers.Location?.OriginalString);
        }
    }

    [Theory]
    [InlineData("/Applications/not-a-guid/Roles")]
    [InlineData("/Applications/not-a-guid/Roles/Create")]
    [InlineData("/Applications/00000000-0000-0000-0000-000000000000/Roles")]
    [InlineData("/Applications/{app}/Roles/Edit/xyz")]
    [InlineData("/Applications/{app}/Roles/Delete/xyz")]
    [InlineData("/Applications/{app}/Roles/Edit/00000000-0000-0000-0000-000000000000")]
    public async Task Bad_or_empty_ids_give_404_not_500(string template)
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("bad"));
        var r = await b.GetAsync(template.Replace("{app}", app));
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
    }

    [Fact]
    public async Task Post_to_a_role_under_the_wrong_app_changes_nothing_for_edit_and_delete()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("w1"));
        var other = await CreateAppAsync(b, Unique("w2"));
        await WebFixture.PostFormAsync(b, $"/Applications/{app}/Roles/Create", new() { ["Name"] = "keepme", ["Description"] = "orig" });
        var id = RoleId(await b.GetStringAsync($"/Applications/{app}/Roles"), "keepme");

        var edit = await WebFixture.PostFormAsync(b, $"/Applications/{other}/Roles/Edit/{id}", new() { ["Name"] = "hijack" }, tokenFrom: $"/Applications/{app}/Roles/Create");
        Assert.Equal(HttpStatusCode.NotFound, edit.StatusCode);
        var del = await WebFixture.PostFormAsync(b, $"/Applications/{other}/Roles/Delete/{id}", new(), tokenFrom: $"/Applications/{app}/Roles/Create");
        Assert.Equal(HttpStatusCode.NotFound, del.StatusCode);
        var list = await b.GetStringAsync($"/Applications/{app}/Roles");
        Assert.Contains("<td>keepme</td>", list);
        Assert.Contains("orig", list);
        Assert.DoesNotContain("hijack", list);
        Assert.DoesNotContain("<td>hijack</td>", await b.GetStringAsync($"/Applications/{other}/Roles"));
    }

    [Fact]
    public async Task Validation_errors_keep_the_form_values_and_show_the_api_text()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("val"));
        var path = $"/Applications/{app}/Roles/Create";
        foreach (var name in new[] { "", "   ", "Has Space", "UPPER", new string('a', 65) })
        {
            var r = await WebFixture.PostFormAsync(b, path, new() { ["Name"] = name, ["Description"] = "keepdesc" });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var html = await r.Content.ReadAsStringAsync();
            Assert.Contains("role=\"alert\"", html);
            Assert.Contains("value=\"keepdesc\"", html);
        }
        var ok64 = await WebFixture.PostFormAsync(b, path, new() { ["Name"] = new string('a', 64), ["Description"] = new string('d', 256) });
        Assert.Equal(HttpStatusCode.Redirect, ok64.StatusCode);
        var over = await WebFixture.PostFormAsync(b, path, new() { ["Name"] = "okname", ["Description"] = new string('d', 257) });
        Assert.Equal(HttpStatusCode.OK, over.StatusCode);
        // form limits mirror the API
        var form = await b.GetStringAsync(path);
        Assert.Contains("maxlength=\"64\"", form);
        Assert.Contains("maxlength=\"256\"", form);
    }

    [Fact]
    public async Task Rename_to_an_existing_name_shows_409_text_and_keeps_both_roles()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("rn"));
        var path = $"/Applications/{app}/Roles";
        await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "one" });
        await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "two" });
        var id = RoleId(await b.GetStringAsync(path), "two");
        var r = await WebFixture.PostFormAsync(b, $"{path}/Edit/{id}", new() { ["Name"] = "one", ["Description"] = "x" });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Contains("already exists", html);
        var list = await b.GetStringAsync(path);
        Assert.Contains("<td>one</td>", list);
        Assert.Contains("<td>two</td>", list);
        // clearing the description works
        await WebFixture.PostFormAsync(b, $"{path}/Edit/{id}", new() { ["Name"] = "two", ["Description"] = "" });
    }

    [Fact]
    public async Task Concurrent_deletes_and_edits_end_in_404_or_redirect_never_500()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("cc"));
        var path = $"/Applications/{app}/Roles";
        await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "victim" });
        var id = RoleId(await b.GetStringAsync(path), "victim");
        var (token, _, version) = await WebFixture.TokenNonceAndVersionAsync(b, $"{path}/Delete/{id}");

        Task<HttpResponseMessage> Post(string url, Dictionary<string, string> f)
        {
            f["__RequestVerificationToken"] = token;
            f["Version"] = version!; // every form was opened at the same version
            return b.PostAsync(url, new FormUrlEncodedContent(f));
        }
        var results = await Task.WhenAll(
            Post($"{path}/Delete/{id}", new()), Post($"{path}/Delete/{id}", new()),
            Post($"{path}/Edit/{id}", new() { ["Name"] = "late" }), Post($"{path}/Delete/{id}", new()));
        foreach (var r in results)
            Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.NotFound or HttpStatusCode.PreconditionFailed, $"unexpected {r.StatusCode}");
        Assert.Contains(results, r => r.StatusCode == HttpStatusCode.Redirect);
        Assert.DoesNotContain("<td>victim</td>", await b.GetStringAsync(path));
    }

    [Fact]
    public async Task Concurrent_creates_of_the_same_name_yield_exactly_one_role()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("cr"));
        var path = $"/Applications/{app}/Roles";
        var token = await WebFixture.TokenAsync(b, path + "/Create");
        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ =>
            b.PostAsync(path + "/Create", new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = "dup", ["__RequestVerificationToken"] = token }))));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.Redirect));
        Assert.All(results.Where(r => r.StatusCode != HttpStatusCode.Redirect), r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Single(Regex.Matches(await b.GetStringAsync(path), "<td>dup</td>"));
    }

    [Fact]
    public async Task Delete_text_matches_the_store_cascade_to_users_and_clients()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("cas"));
        var path = $"/Applications/{app}/Roles";
        await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "held" });
        var id = RoleId(await b.GetStringAsync(path), "held");
        var confirm = await b.GetStringAsync($"{path}/Delete/{id}");
        Assert.Contains("removed from every user and service client", confirm);

        var api = await ApiAdminAsync();
        var u = Unique("cu");
        var created = await api.PostAsJsonAsync("/v1/users", new { username = u, email = $"{u}@example.com", displayName = "x", kind = "person" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var uid = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        Assert.True((await api.PutAsync($"/v1/users/{uid}/roles/{id}", null)).IsSuccessStatusCode);
        var cn = Unique("cc");
        var cc = await api.PostAsJsonAsync("/v1/clients", new { name = cn, application = Guid.Parse(app), isActive = true });
        Assert.Equal(HttpStatusCode.Created, cc.StatusCode);
        var cid = (await cc.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        Assert.True((await api.PutAsync($"/v1/clients/{cid}/roles/{id}", null)).IsSuccessStatusCode);

        var del = await WebFixture.PostFormAsync(b, $"{path}/Delete/{id}", new());
        Assert.Equal(HttpStatusCode.Redirect, del.StatusCode);
        Assert.Empty((await api.GetFromJsonAsync<JsonElement>($"/v1/users/{uid}/roles")).GetProperty("items").EnumerateArray());
        Assert.Empty((await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{cid}/roles")).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/v1/users/{uid}")).StatusCode); // the user itself survives
    }

    [Fact]
    public async Task Reserved_app_other_pages_and_done_message_are_safe()
    {
        var b = await _f.SignedInAsync();
        var gk = Regex.Match(await b.GetStringAsync("/Applications"), "<td>gatekeeper</td>\\s*<td><code>([0-9a-f-]{36})</code>").Groups[1].Value;
        var path = $"/Applications/{gk}/Roles";
        // Edit/Delete GET pages for the reserved admin role carry no form
        var api = await ApiAdminAsync();
        var rid = (await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles")).GetProperty("items")[0].GetProperty("id").GetString();
        foreach (var url in new[] { $"{path}/Edit/{rid}", $"{path}/Delete/{rid}" })
        {
            var html = await b.GetStringAsync(url);
            Assert.Contains("read-only", html);
            Assert.DoesNotContain("name=\"Name\"", html);
            Assert.DoesNotContain(">Delete</button>", html);
        }
        // an unknown or hostile done key is ignored, never echoed
        var h = await b.GetStringAsync($"{path}?done=%3Cscript%3Ealert(1)%3C/script%3E");
        Assert.DoesNotContain("alert(1)", h);
    }
}
