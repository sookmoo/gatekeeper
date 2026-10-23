extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 6e: the edit and delete forms carry the API's version and send it as If-Match.</summary>
public class Versions6eTests : IClassFixture<WebFixture>
{
    private const string Changed = "Changed by someone else since you opened it. The current values are shown; apply your change again.";
    private const string Missing = "The form is out of date or incomplete. The current values are shown; apply your change again.";
    private const string Password = "a long enough password";
    private readonly WebFixture _f;

    public Versions6eTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<HttpClient> ApiAdminAsync(WebFixture f)
    {
        var c = f.Api.CreateClient();
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

    private static async Task<long> VersionAsync(HttpClient api, string path) => (await GetAsync(api, path)).GetProperty("version").GetInt64();

    private static async Task PatchOkAsync(HttpClient api, string path, object body) =>
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync(path, body)).StatusCode);

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static string HiddenVersion(string html) => WebUtility.HtmlDecode(Regex.Match(html, "<input[^>]*name=\"Version\"[^>]*>").Value is { Length: > 0 } tag ? Regex.Match(tag, "value=\"([^\"]*)\"").Groups[1].Value : "");

    private static string Field(string html, string name) => WebUtility.HtmlDecode(Regex.Match(html, $"name=\"{name}\"[^>]*value=\"([^\"]*)\"").Groups[1].Value);

    /// <summary>What a browser posts back from the form on <paramref name="html"/> before the user types: every hidden input.</summary>
    private static List<KeyValuePair<string, string>> HiddenInputs(string html)
    {
        var list = new List<KeyValuePair<string, string>>();
        var main = html[Math.Max(0, html.IndexOf("<main", StringComparison.Ordinal))..]; // not the sign-out form of the layout
        foreach (Match m in Regex.Matches(main, "<input[^>]*type=\"hidden\"[^>]*>"))
        {
            var name = Regex.Match(m.Value, "name=\"([^\"]*)\"").Groups[1].Value;
            var value = WebUtility.HtmlDecode(Regex.Match(m.Value, "value=\"([^\"]*)\"").Groups[1].Value);
            list.Add(new(name, value));
        }
        return list;
    }

    private static List<KeyValuePair<string, string>> With(List<KeyValuePair<string, string>> form, string name, string? value)
    {
        form.RemoveAll(p => p.Key == name);
        if (value is not null) form.Add(new(name, value));
        return form;
    }

    private static Task<HttpResponseMessage> PostAsync(HttpClient b, string path, List<KeyValuePair<string, string>> form) =>
        b.PostAsync(path, new FormUrlEncodedContent(form));

    // ---- hidden version on every form -------------------------------------------------------------------------------

    private sealed record Target(string Path, string Resource, bool IsEdit, Func<HttpClient, Task> ChangeElsewhere, Func<HttpClient, Task<bool>> Intact, Func<List<KeyValuePair<string, string>>, List<KeyValuePair<string, string>>> Type, string Marker);

    private async Task<Target> MakeAsync(string kind, string flavour)
    {
        var api = await ApiAdminAsync(_f);
        var edit = flavour == "edit";
        switch (kind)
        {
            case "user":
            {
                var name = Unique("u");
                var id = await CreateAsync(api, "/v1/users", new { username = name, email = name + "@example.com", displayName = "Original", kind = "person" });
                return new($"/Users/{(edit ? "Edit" : "Delete")}/{id}", $"/v1/users/{id}", edit,
                    c => PatchOkAsync(c, $"/v1/users/{id}", new { displayName = "Theirs" }),
                    async c => edit ? (await GetAsync(c, $"/v1/users/{id}")).GetProperty("displayName").GetString() == "Original" : (await c.GetAsync($"/v1/users/{id}")).IsSuccessStatusCode,
                    f =>
                    {
                        // what the browser sends from the visible fields, as loaded, plus the typed display name
                        With(f, "Username", f.First(p => p.Key == "OrigUsername").Value);
                        With(f, "Email", f.First(p => p.Key == "OrigEmail").Value);
                        With(f, "Kind", "person");
                        With(f, "Expiry", "");
                        f.Add(new("IsActive", "true"));
                        return With(f, "DisplayName", "Mine");
                    }, "Original");
            }
            case "client":
            {
                var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
                var name = Unique("c");
                var id = await CreateAsync(api, "/v1/clients", new { name, application = app, isActive = true });
                return new($"/Clients/{(edit ? "Edit" : "Delete")}/{id}", $"/v1/clients/{id}", edit,
                    c => PatchOkAsync(c, $"/v1/clients/{id}", new { isActive = false }),
                    async c => edit ? (await GetAsync(c, $"/v1/clients/{id}")).GetProperty("name").GetString() == name : (await c.GetAsync($"/v1/clients/{id}")).IsSuccessStatusCode,
                    f => With(f, "Name", Unique("mine")), name);
            }
            case "app":
            {
                var name = Unique("app");
                var id = await CreateAsync(api, "/v1/applications", new { name });
                return new($"/Applications/{(edit ? "Edit" : "Delete")}/{id}", $"/v1/applications/{id}", edit,
                    c => PatchOkAsync(c, $"/v1/applications/{id}", new { name = Unique("theirs") }),
                    async c => edit ? (await GetAsync(c, $"/v1/applications/{id}")).GetProperty("name").GetString() == name : (await c.GetAsync($"/v1/applications/{id}")).IsSuccessStatusCode,
                    f => With(f, "Name", Unique("mine")), name);
            }
            default:
            {
                var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
                var name = Unique("r");
                var id = await CreateAsync(api, $"/v1/applications/{app}/roles", new { name, description = "Original" });
                return new($"/Applications/{app}/Roles/{(edit ? "Edit" : "Delete")}/{id}", $"/v1/roles/{id}", edit,
                    c => PatchOkAsync(c, $"/v1/roles/{id}", new { description = "Theirs" }),
                    async c => edit ? (await GetAsync(c, $"/v1/roles/{id}")).GetProperty("description").GetString() == "Original" : (await c.GetAsync($"/v1/roles/{id}")).IsSuccessStatusCode,
                    f => With(With(f, "Name", name), "Description", "Mine"), "Original");
            }
        }
    }

    public static IEnumerable<object[]> Pages() =>
        from kind in new[] { "user", "client", "app", "role" }
        from flavour in new[] { "edit", "delete" }
        select new object[] { kind, flavour };

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task The_form_carries_the_current_version_as_a_hidden_number(string kind, string flavour)
    {
        var t = await MakeAsync(kind, flavour);
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();
        var v = await VersionAsync(api, t.Resource);
        var html = await b.GetStringAsync(t.Path);
        Assert.Matches("<input type=\"hidden\" name=\"Version\" value=\"\\d+\">", html);
        Assert.Equal(v.ToString(), HiddenVersion(html));
        await t.ChangeElsewhere(api);
        var bumped = await VersionAsync(api, t.Resource);
        Assert.True(bumped > v);
        Assert.Equal(bumped.ToString(), HiddenVersion(await b.GetStringAsync(t.Path)));
    }

    // ---- two sessions: the second save/delete is refused and shows the fresh values ----------------------------------

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task A_change_made_meanwhile_gives_the_412_text_with_fresh_values_and_keeps_the_first_change(string kind, string flavour)
    {
        var t = await MakeAsync(kind, flavour);
        var api = await ApiAdminAsync(_f);
        var second = await _f.SignedInAsync();
        var opened = await second.GetStringAsync(t.Path); // the second administrator opens the form
        var form = HiddenInputs(opened);
        var firstVersion = HiddenVersion(opened);

        await t.ChangeElsewhere(api); // the first administrator saves
        var afterFirst = await GetAsync(api, t.Resource);
        var freshVersion = afterFirst.GetProperty("version").GetInt64();
        Assert.NotEqual(firstVersion, freshVersion.ToString());

        if (t.IsEdit) t.Type(form);
        var resp = await PostAsync(second, t.Path, form);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.PreconditionFailed, resp.StatusCode);
        Assert.Equal(Changed, Alert(html));
        Assert.Equal(freshVersion.ToString(), HiddenVersion(html)); // fresh version for the next try
        Assert.Equal(freshVersion, (await GetAsync(api, t.Resource)).GetProperty("version").GetInt64()); // nothing was written

        if (t.IsEdit)
        {
            // the first change is shown (and still stored); what the second typed is not
            switch (kind)
            {
                case "user": Assert.Equal("Theirs", Field(html, "DisplayName")); break;
                case "role": Assert.Equal("Theirs", Field(html, "Description")); break;
                case "client": Assert.DoesNotContain("checked", Regex.Match(html, "<input type=\"checkbox\"[^>]*>").Value); break;
                default: Assert.Equal(afterFirst.GetProperty("name").GetString(), Field(html, "Name")); break;
            }
        }
        else
        {
            Assert.True(await t.Intact(api)); // still there
        }

        // Applying the change again with the fresh form works; it is the user's decision, not an automatic retry.
        var retryForm = HiddenInputs(html);
        if (t.IsEdit) t.Type(retryForm);
        var retry = await PostAsync(second, t.Path, retryForm);
        Assert.Equal(HttpStatusCode.Redirect, retry.StatusCode);
        if (!t.IsEdit) Assert.Equal(HttpStatusCode.NotFound, (await api.GetAsync(t.Resource)).StatusCode);
    }

    // ---- missing, garbage and forged versions never become an unconditional write ----------------------------------

    private static readonly string[] BadVersions = ["", "abc", "0", "-1", "1e3", " 3", "3 ", "\"3\"", "W/\"3\"", "*", "99999999999999999999", "1.5", "\"><script>alert(1)</script>", "1,2"];

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task A_garbage_version_is_refused_with_fresh_values_and_nothing_is_written(string kind, string flavour)
    {
        var t = await MakeAsync(kind, flavour);
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();
        var before = (await GetAsync(api, t.Resource)).ToString();
        foreach (var bad in BadVersions)
        {
            var form = HiddenInputs(await b.GetStringAsync(t.Path));
            if (t.IsEdit) t.Type(form);
            With(form, "Version", bad);

            var resp = await PostAsync(b, t.Path, form);
            var html = await resp.Content.ReadAsStringAsync();
            Assert.True(HttpStatusCode.BadRequest == resp.StatusCode, $"version '{bad}' answered {(int)resp.StatusCode}");
            Assert.Equal(Missing, Alert(html));
            Assert.DoesNotContain("<script>alert", html);
            Assert.Equal(before, (await GetAsync(api, t.Resource)).ToString());
            Assert.Matches("name=\"Version\" value=\"\\d+\"", html); // the form is usable again with the current version
        }
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task A_version_sent_twice_or_with_a_leading_zero_is_refused_and_nothing_is_written(string kind, string flavour)
    {
        var t = await MakeAsync(kind, flavour);
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();
        var before = (await GetAsync(api, t.Resource)).ToString();
        var current = (await GetAsync(api, t.Resource)).GetProperty("version").GetInt64().ToString();
        foreach (var versions in new[] { new[] { "999999", current }, new[] { current, "999999" }, new[] { current, current } })
        {
            var form = HiddenInputs(await b.GetStringAsync(t.Path));
            if (t.IsEdit) t.Type(form);
            With(form, "Version", null);
            foreach (var v in versions) form.Add(new("Version", v));
            var resp = await PostAsync(b, t.Path, form);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
            Assert.Equal(Missing, Alert(await resp.Content.ReadAsStringAsync()));
            Assert.Equal(before, (await GetAsync(api, t.Resource)).ToString());
        }
        var padded = HiddenInputs(await b.GetStringAsync(t.Path));
        if (t.IsEdit) t.Type(padded);
        With(padded, "Version", "0" + current);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(b, t.Path, padded)).StatusCode);
        Assert.Equal(before, (await GetAsync(api, t.Resource)).ToString());
    }

    [Fact]
    public async Task A_refused_delete_that_is_not_stale_keeps_the_posted_version_in_the_form()
    {
        // The API refuses every delete with 409 (a stub); the current version is 1 but the form posted 7: a retry must still carry 7.
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            r.Method == HttpMethod.Delete && r.RequestUri!.AbsolutePath.StartsWith("/v1/", StringComparison.Ordinal) && !r.RequestUri.AbsolutePath.Contains("auth")
                ? new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("{\"title\":\"Conflict\",\"detail\":\"refused\"}", System.Text.Encoding.UTF8, "application/json") }
                : null)));
        using var fixture = f;
        var api = await ApiAdminAsync(f);
        var b = await f.SignedInAsync();
        var app = await CreateAsync(api, "/v1/applications", new { name = Unique("a") });
        var client = await CreateAsync(api, "/v1/clients", new { name = Unique("c"), application = app, isActive = true });
        var role = await CreateAsync(api, $"/v1/applications/{app}/roles", new { name = Unique("r"), description = "" });
        var n = Unique("u");
        var user = await CreateAsync(api, "/v1/users", new { username = n, email = n + "@example.com", displayName = "", kind = "person" });
        foreach (var path in new[] { $"/Applications/Delete/{app}", $"/Clients/Delete/{client}", $"/Applications/{app}/Roles/Delete/{role}", $"/Users/Delete/{user}" })
        {
            var form = HiddenInputs(await b.GetStringAsync(path));
            Assert.Equal("1", form.First(p => p.Key == "Version").Value);
            With(form, "Version", "7");
            var resp = await PostAsync(b, path, form);
            var html = await resp.Content.ReadAsStringAsync();
            Assert.NotEmpty(Alert(html)); // the refusal is shown
            Assert.Equal("7", HiddenVersion(html));
        }
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task A_missing_version_field_is_refused_and_nothing_is_written(string kind, string flavour)
    {
        var t = await MakeAsync(kind, flavour);
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();
        var before = (await GetAsync(api, t.Resource)).ToString();
        var form = HiddenInputs(await b.GetStringAsync(t.Path));
        if (t.IsEdit) t.Type(form);
        With(form, "Version", null);

        var resp = await PostAsync(b, t.Path, form);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Equal(Missing, Alert(await resp.Content.ReadAsStringAsync()));
        Assert.Equal(before, (await GetAsync(api, t.Resource)).ToString());
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task A_forged_version_is_a_412_and_nothing_is_written(string kind, string flavour)
    {
        var t = await MakeAsync(kind, flavour);
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();
        var before = (await GetAsync(api, t.Resource)).ToString();
        foreach (var forged in new[] { "999", "2" }) // 2 is not the stored version of a fresh row
        {
            var form = HiddenInputs(await b.GetStringAsync(t.Path));
            if (t.IsEdit) t.Type(form);
            With(form, "Version", forged);
            var resp = await PostAsync(b, t.Path, form);
            Assert.Equal(HttpStatusCode.PreconditionFailed, resp.StatusCode);
            Assert.Equal(Changed, Alert(await resp.Content.ReadAsStringAsync()));
            Assert.Equal(before, (await GetAsync(api, t.Resource)).ToString());
        }
    }

    // ---- a real browser body still works --------------------------------------------------------------------------

    [Fact]
    public async Task A_browser_body_with_hidden_and_checkbox_values_saves_a_user_and_a_client()
    {
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();

        var user = await MakeAsync("user", "edit");
        var form = HiddenInputs(await b.GetStringAsync(user.Path));
        Assert.Contains(form, p => p is { Key: "IsActive", Value: "false" });
        form.AddRange([new("Username", Field(await b.GetStringAsync(user.Path), "Username")), new("Email", Field(await b.GetStringAsync(user.Path), "Email")), new("Kind", "person"), new("Expiry", ""), new("IsActive", "true")]);
        With(form, "DisplayName", "Browser");
        var saved = await PostAsync(b, user.Path, form);
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        var userId = user.Resource;
        var stored = await GetAsync(api, userId);
        Assert.Equal("Browser", stored.GetProperty("displayName").GetString());
        Assert.True(stored.GetProperty("isActive").GetBoolean()); // hidden false + checked true: stays active
        Assert.Equal(2, stored.GetProperty("version").GetInt64());

        var client = await MakeAsync("client", "edit");
        var cform = HiddenInputs(await b.GetStringAsync(client.Path));
        cform.Add(new("IsActive", "true"));
        With(cform, "Name", Unique("renamed"));
        Assert.Equal(HttpStatusCode.Redirect, (await PostAsync(b, client.Path, cform)).StatusCode);
        var c = await GetAsync(api, client.Resource);
        Assert.StartsWith("renamed", c.GetProperty("name").GetString());
        Assert.True(c.GetProperty("isActive").GetBoolean());
        Assert.Equal(2, c.GetProperty("version").GetInt64());
    }

    // ---- self-disable (5d) -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Disabling_oneself_on_a_stale_form_keeps_the_web_session_and_ends_it_only_when_the_patch_succeeds()
    {
        var api = await ApiAdminAsync(_f);
        var name = Unique("adm");
        var id = await CreateAsync(api, "/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "person" });
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var apps = await GetAsync(api, "/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var adminRole = (await GetAsync(api, $"/v1/applications/{gk}/roles")).GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null)).StatusCode);
        var b = _f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);

        var path = $"/Users/Edit/{id}";
        var form = HiddenInputs(await b.GetStringAsync(path));
        form.AddRange([new("Username", name), new("Email", name + "@example.com"), new("Kind", "person"), new("Expiry", "")]);
        await PatchOkAsync(api, $"/v1/users/{id}", new { displayName = "Edited elsewhere" }); // the form is now stale

        var stale = await PostAsync(b, path, With(With(form, "IsActive", "false"), "DisplayName", ""));
        var html = await stale.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal(Changed, Alert(html).Trim());
        Assert.True((await GetAsync(api, $"/v1/users/{id}")).GetProperty("isActive").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode); // the session lives
        Assert.Equal("Edited elsewhere", Field(html, "DisplayName"));

        // Apply again on the fresh form: now the PATCH succeeds and the session ends.
        var fresh = HiddenInputs(html);
        fresh.AddRange([new("Username", name), new("Email", name + "@example.com"), new("Kind", "person"), new("Expiry", ""), new("DisplayName", "Edited elsewhere")]);
        With(fresh, "IsActive", "false");
        var done = await PostAsync(b, path, fresh);
        Assert.Equal(HttpStatusCode.Redirect, done.StatusCode);
        Assert.Equal("/Login?ended=1", done.Headers.Location?.OriginalString);
        Assert.False((await GetAsync(api, $"/v1/users/{id}")).GetProperty("isActive").GetBoolean());
        Assert.Equal("/Login", (await b.GetAsync("/Users")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Deleting_oneself_on_a_stale_confirmation_keeps_the_web_session()
    {
        var api = await ApiAdminAsync(_f);
        var name = Unique("adm");
        var id = await CreateAsync(api, "/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "person" });
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var apps = await GetAsync(api, "/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var adminRole = (await GetAsync(api, $"/v1/applications/{gk}/roles")).GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null)).StatusCode);
        var b = _f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);

        var path = $"/Users/Delete/{id}";
        var form = HiddenInputs(await b.GetStringAsync(path));
        await PatchOkAsync(api, $"/v1/users/{id}", new { displayName = "Edited elsewhere" });
        var stale = await PostAsync(b, path, form);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/v1/users/{id}")).StatusCode);
    }

    // ---- application list cache --------------------------------------------------------------------------------------

    [Fact]
    public async Task A_stale_application_rename_shows_the_current_name_and_the_save_after_it_renames()
    {
        var api = await ApiAdminAsync(_f);
        var b = await _f.SignedInAsync();
        var name = Unique("app");
        var id = await CreateAsync(api, "/v1/applications", new { name });
        var path = $"/Applications/Edit/{id}";
        var form = HiddenInputs(await b.GetStringAsync(path));
        var theirs = Unique("theirs");
        await PatchOkAsync(api, $"/v1/applications/{id}", new { name = theirs });

        var stale = await PostAsync(b, path, With(form, "Name", Unique("mine")));
        var html = await stale.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal(theirs, Field(html, "Name"));

        var mine = Unique("mine");
        var ok = await PostAsync(b, path, With(HiddenInputs(html), "Name", mine));
        Assert.Equal("/Applications?done=renamed", ok.Headers.Location?.OriginalString);
        Assert.Equal(mine, (await GetAsync(api, $"/v1/applications/{id}")).GetProperty("name").GetString());
    }
}
