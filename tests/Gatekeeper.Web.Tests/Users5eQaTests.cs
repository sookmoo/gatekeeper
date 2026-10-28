extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent QA gap tests for slice 5e (written from the spec in status.md, not from the pages).</summary>
public class Users5eQaTests : IClassFixture<WebFixture>
{
    private const string Password = "a long enough password";
    private readonly WebFixture _f;

    public Users5eQaTests(WebFixture f) => _f = f;

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

    private static async Task<Guid> UserAsync(HttpClient api, string name) =>
        await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "person" }));

    private static async Task<Guid> AppAsync(HttpClient api, string name) =>
        await IdOf(await api.PostAsJsonAsync("/v1/applications", new { name }));

    private static async Task<Guid> RoleAsync(HttpClient api, Guid app, string name) =>
        await IdOf(await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name, description = "d" }));

    private static async Task<List<Guid>> UserRolesAsync(HttpClient api, Guid user) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/roles?limit=200")).GetProperty("items").EnumerateArray().Select(r => r.GetProperty("id").GetGuid()).ToList();

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private async Task<(HttpClient Browser, Guid Id, string Name)> SecondAdminAsync()
    {
        var api = await ApiAdminAsync(_f);
        var name = Unique("qadm");
        var id = await UserAsync(api, name);
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var apps = await api.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        var admin = roles.GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{admin}", null)).StatusCode);
        var b = _f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
        return (b, id, name);
    }

    [Fact]
    public async Task Adding_a_role_the_user_already_holds_is_not_a_server_error_and_does_not_duplicate()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("held"));
        var app = await AppAsync(api, Unique("heldapp"));
        var role = await RoleAsync(api, app, "r");
        var fields = new Dictionary<string, string> { ["app"] = app.ToString(), ["RoleId"] = role.ToString() };
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", fields, $"/Users/{user}/Roles/Add?app={app}")).StatusCode);
        var again = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", fields, $"/Users/{user}/Roles/Add?app={app}");
        Assert.True((int)again.StatusCode < 500, again.StatusCode.ToString());
        Assert.Equal([role], await UserRolesAsync(api, user));
    }

    [Fact]
    public async Task A_role_or_app_deleted_between_the_two_steps_gives_404_and_changes_nothing()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("gone"));
        var app = await AppAsync(api, Unique("goneapp"));
        var role = await RoleAsync(api, app, "r");
        var keep = await RoleAsync(api, app, "keep");
        Assert.Contains("<option", await b.GetStringAsync($"/Users/{user}/Roles/Add?app={app}"));
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/roles/{role}")).StatusCode);
        var r = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = role.ToString() }, $"/Users/{user}/Roles/Add?app={app}");
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        // the app goes too (its last role first)
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync($"/v1/roles/{keep}")).StatusCode);
        var del = await api.DeleteAsync($"/v1/applications/{app}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);
        var r2 = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = keep.ToString() }, $"/Users/{user}/Roles");
        Assert.Equal(HttpStatusCode.NotFound, r2.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/{user}/Roles/Add?app={app}")).StatusCode);
        Assert.Empty(await UserRolesAsync(api, user));
    }

    [Fact]
    public async Task Application_names_come_with_the_roles_without_extra_lookups_and_a_role_without_one_shows_unknown()
    {
        var calls = new List<string>();
        var items = new List<string>();
        var userId = Guid.NewGuid();
        var phantomApp = Guid.NewGuid();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            lock (calls) calls.Add(r.Method + " " + r.RequestUri!.PathAndQuery);
            var path = r.RequestUri!.AbsolutePath;
            if (path == $"/v1/users/{userId}")
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($"{{\"id\":\"{userId}\",\"username\":\"stubbed\",\"email\":\"e@example.com\",\"displayName\":\"\",\"isActive\":true,\"kind\":\"person\",\"expiresAt\":null}}", System.Text.Encoding.UTF8, "application/json") };
            if (path == $"/v1/users/{userId}/roles")
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"items\":[" + string.Join(',', items) + "],\"nextCursor\":null}", System.Text.Encoding.UTF8, "application/json") };
            return null;
        })));
        using var _ = f;
        var api = await ApiAdminAsync(f);
        var names = new List<string>();
        for (var i = 0; i < 5; i++)
        {
            var n = Unique("nm" + i);
            names.Add(n);
            var a = await AppAsync(api, n);
            items.Add($"{{\"id\":\"{await RoleAsync(api, a, "role" + i)}\",\"appId\":\"{a}\",\"appName\":\"{n}\",\"name\":\"role{i}\",\"description\":\"\"}}");
        }
        items.Add($"{{\"id\":\"{Guid.NewGuid()}\",\"appId\":\"{phantomApp}\",\"name\":\"ghost\",\"description\":\"\"}}");
        var b = await f.SignedInAsync();
        calls.Clear();
        var html = await b.GetStringAsync($"/Users/{userId}/Roles");
        foreach (var n in names) Assert.Contains($"<td>{n}</td>", html);
        Assert.Contains("<td>(unknown)</td>", html);
        // slice 8g: the API names each role's application, so the page makes no application lookups at all
        Assert.DoesNotContain(calls, c => c.Contains("/v1/applications"));
    }

    [Fact]
    public async Task Names_of_up_to_three_apps_and_more_than_three_apps_are_all_shown()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("fivenm"));
        var names = new List<string>();
        for (var i = 0; i < 5; i++)
        {
            var n = Unique("fv" + i);
            names.Add(n);
            await api.PutAsync($"/v1/users/{user}/roles/{await RoleAsync(api, await AppAsync(api, n), "x" + i)}", null);
        }
        var html = await b.GetStringAsync($"/Users/{user}/Roles");
        foreach (var n in names) Assert.Contains($"<td>{n}</td>", html);
        Assert.DoesNotContain("(unknown)", html);
    }

    [Fact]
    public async Task The_add_form_caps_at_100_roles_with_a_More_link_that_keeps_the_app_and_reaches_the_rest()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("cap"));
        var app = await AppAsync(api, Unique("capapp"));
        for (var i = 0; i < 101; i++) await RoleAsync(api, app, $"r{i:000}");
        var first = await b.GetStringAsync($"/Users/{user}/Roles/Add?app={app}");
        Assert.Equal(100, Regex.Matches(first, "<option value=").Count);
        var more = System.Net.WebUtility.HtmlDecode(Regex.Match(first, "href=\"([^\"]*)\">More").Groups[1].Value);
        Assert.Contains($"app={app}", more);
        Assert.Contains("cursor=", more);
        var second = await b.GetStringAsync(more);
        Assert.Single(Regex.Matches(second, "<option value="));
        Assert.DoesNotContain(">More<", second);
        // the second page's role can be added (the POST carries the app, not the cursor)
        var rid = Regex.Match(second, "<option value=\"([^\"]+)\"").Groups[1].Value;
        var ok = await WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = rid }, $"/Users/{user}/Roles/Add?app={app}");
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
    }

    [Fact]
    public async Task Crafted_two_step_parameters_never_change_anything_unexpected()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("craft"));
        var app = await AppAsync(api, Unique("craftapp"));
        var role = await RoleAsync(api, app, "r");
        foreach (var path in new[]
        {
            $"/Users/{user}/Roles/Add?app=not-a-guid",
            $"/Users/{user}/Roles/Add?app={app}&app={Guid.NewGuid()}",
            $"/Users/{user}/Roles/Add?app={app}&cursor=%00%ff",
            $"/Users/{user}/Roles/Add?app=&cursor=x",
            $"/Users/{user}/Roles/Add?RoleId={role}",
        })
        {
            var r = await b.GetAsync(path);
            Assert.True((int)r.StatusCode < 500, path + " -> " + r.StatusCode);
        }
        Assert.Empty(await UserRolesAsync(api, user)); // GET never assigns
    }

    [Fact]
    public async Task The_admin_role_goes_only_to_a_person_and_the_error_is_shown_on_the_form()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var apps = await api.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        var admin = roles.GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        var test = await IdOf(await api.PostAsJsonAsync("/v1/users", new { username = Unique("tst"), email = Unique("t") + "@example.com", displayName = "", kind = "test" }));
        var r = await WebFixture.PostFormAsync(b, $"/Users/{test}/Roles/Add", new() { ["app"] = gk.ToString(), ["RoleId"] = admin.ToString() }, $"/Users/{test}/Roles/Add?app={gk}");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("Only a person can hold the admin role.", Alert(await r.Content.ReadAsStringAsync()));
        Assert.Empty(await UserRolesAsync(api, test));
    }

    [Fact]
    public async Task Removing_an_own_role_that_is_not_the_gatekeeper_admin_keeps_the_session()
    {
        var (b, id, _) = await SecondAdminAsync();
        var api = await ApiAdminAsync(_f);
        var app = await AppAsync(api, Unique("selfapp"));
        var look = await RoleAsync(api, app, "admin"); // same name, other application: not the UI's admin role
        await api.PutAsync($"/v1/users/{id}/roles/{look}", null);
        var page = await b.GetStringAsync($"/Users/{id}/Roles/Remove/{look}");
        Assert.DoesNotContain("your own admin role", page);
        var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Roles/Remove/{look}", new());
        Assert.Equal($"/Users/{id}/Roles?done=removed", r.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
    }

    [Fact]
    public async Task Parallel_adds_and_removes_of_one_role_end_in_a_consistent_state_without_5xx()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("par"));
        var app = await AppAsync(api, Unique("parapp"));
        var role = await RoleAsync(api, app, "r");
        var add = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Add", new() { ["app"] = app.ToString(), ["RoleId"] = role.ToString() }, $"/Users/{user}/Roles/Add?app={app}")));
        Assert.All(add, r => Assert.True((int)r.StatusCode < 500, r.StatusCode.ToString()));
        Assert.Equal([role], await UserRolesAsync(api, user));
        var rem = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => WebFixture.PostFormAsync(b, $"/Users/{user}/Roles/Remove/{role}", new(), $"/Users/{user}/Roles")));
        Assert.All(rem, r => Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.NotFound, r.StatusCode.ToString()));
        Assert.Contains(rem, r => r.StatusCode == HttpStatusCode.Redirect);
        Assert.Empty(await UserRolesAsync(api, user));
    }

    [Theory]
    [InlineData(11, false)]
    [InlineData(12, true)]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public async Task Password_length_follows_the_api_rules_exactly(int length, bool accepted)
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("len"));
        var pw = new string('p', length - 1) + "Q";
        var r = await WebFixture.PostFormAsync(b, $"/Users/{user}/Password", new() { ["Password"] = pw, ["Confirm"] = pw }, $"/Users/{user}/Password");
        var body = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain(pw, body);
        if (accepted) Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Contains("12 to 128", Alert(body));
        }
    }

    [Fact]
    public async Task A_password_with_control_characters_is_refused_with_the_fixed_text_and_never_echoed()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("ctl"));
        var pw = "valid-looking-pw\u0007\u0001zz";
        var r = await WebFixture.PostFormAsync(b, $"/Users/{user}/Password", new() { ["Password"] = pw, ["Confirm"] = pw }, $"/Users/{user}/Password");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain("valid-looking-pw", body);
        Assert.Contains("12 to 128", Alert(body));
    }

    [Fact]
    public async Task A_mismatch_for_oneself_keeps_the_session_and_setting_someone_elses_password_keeps_it_too()
    {
        var (b, id, name) = await SecondAdminAsync();
        var api = await ApiAdminAsync(_f);
        var r = await WebFixture.PostFormAsync(b, $"/Users/{id}/Password", new() { ["Password"] = "first long password", ["Confirm"] = "other long password" }, $"/Users/{id}/Password");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
        var other = await UserAsync(api, Unique("oth"));
        var ok = await WebFixture.PostFormAsync(b, $"/Users/{other}/Password", new() { ["Password"] = "someone elses password", ["Confirm"] = "someone elses password" }, $"/Users/{other}/Password");
        Assert.Equal($"/Users/{other}/Password?done=set", ok.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
        // old password of self still works: nothing was changed
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(_f.Browser(), "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
    }

    [Fact]
    public async Task Posting_a_password_for_an_unknown_user_is_404_and_the_done_text_is_fixed()
    {
        var b = await _f.SignedInAsync();
        var r = await WebFixture.PostFormAsync(b, $"/Users/{Guid.NewGuid()}/Password", new() { ["Password"] = "some long password", ["Confirm"] = "some long password" }, "/Users");
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        var api = await ApiAdminAsync(_f);
        var user = await UserAsync(api, Unique("done"));
        var html = await b.GetStringAsync($"/Users/{user}/Password?done=<script>alert(1)</script>");
        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("class=\"notice\"", html);
    }
}
