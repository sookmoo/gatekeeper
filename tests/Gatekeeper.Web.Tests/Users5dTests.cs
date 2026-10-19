extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

public class Users5dTests : IClassFixture<WebFixture>
{
    private const string Password = "a long enough password";
    private readonly WebFixture _f;

    public Users5dTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static string Minute(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm");

    private static async Task<HttpClient> ApiAdminAsync(WebFixture f, string user = WebFixture.AdminName, string password = WebFixture.AdminPassword)
    {
        var c = f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = user, password, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private Task<HttpClient> ApiAdminAsync() => ApiAdminAsync(_f);

    private static async Task<Guid> ApiCreateAsync(HttpClient api, string username, string kind = "person", string? displayName = null, string? email = null)
    {
        var r = await api.PostAsJsonAsync("/v1/users", new { username, email = email ?? username + "@example.com", displayName = displayName ?? "", kind });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<JsonElement> ApiUserAsync(HttpClient api, Guid id) => await api.GetFromJsonAsync<JsonElement>($"/v1/users/{id}");

    private static async Task<Guid> IdOfAsync(HttpClient api, string username) =>
        (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + Uri.EscapeDataString(username))).GetProperty("items")[0].GetProperty("id").GetGuid();

    private static string Row(string html, string username)
    {
        var m = Regex.Match(html, $"<tr>(?:(?!</tr>).)*?<td>{Regex.Escape(username)}</td>.*?</tr>", RegexOptions.Singleline);
        Assert.True(m.Success, "no row for " + username);
        return m.Value;
    }

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static Gatekeeper.Application.IUserRepository Repo(WebFixture f) => f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();

    // The API caches "is still an administrator" for a few seconds; tests that remove access clear it so the next request sees the change.
    private static void ForgetAdminCache(WebFixture f) => ((MemoryCache)f.Api.Services.GetRequiredService<IMemoryCache>()).Clear();

    // A second administrator with its own password and web session.
    private async Task<(HttpClient Browser, Guid Id, string Name)> SecondAdminAsync()
    {
        var api = await ApiAdminAsync();
        var name = Unique("adm");
        var id = await ApiCreateAsync(api, name);
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var apps = await api.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        var adminRole = roles.GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{adminRole}", null)).StatusCode);
        var b = _f.Browser();
        var login = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password });
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        return (b, id, name);
    }

    [Fact]
    public async Task User_pages_need_a_session_and_post_needs_the_antiforgery_token()
    {
        var b = _f.Browser();
        var id = Guid.NewGuid();
        foreach (var path in new[] { "/Users", "/Users/Create", $"/Users/Edit/{id}", $"/Users/Delete/{id}" })
        {
            var resp = await b.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.Equal("/Login", resp.Headers.Location?.OriginalString);
        }

        var s = await _f.SignedInAsync();
        var empty = new FormUrlEncodedContent(new Dictionary<string, string> { ["Username"] = "csrf-user", ["Email"] = "c@example.com", ["Kind"] = "person" });
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync("/Users/Create", empty)).StatusCode);
        var name = Unique("keep");
        var uid = await ApiCreateAsync(await ApiAdminAsync(), name);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/Edit/{uid}", empty)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Users/Delete/{uid}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Contains($"<td>{name}</td>", await s.GetStringAsync("/Users?username=" + name));
        Assert.DoesNotContain("csrf-user", await s.GetStringAsync("/Users"));
        Assert.Contains("href=\"/Users\"", await s.GetStringAsync("/Applications")); // navigation entry
    }

    [Fact]
    public async Task Users_can_be_created_edited_and_deleted_with_confirmation()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var name = Unique("rt");

        var created = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["DisplayName"] = "Round Trip", ["Kind"] = "person", ["Expiry"] = "" });
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.Equal("/Users?done=created", created.Headers.Location?.OriginalString);
        var list = await b.GetStringAsync("/Users?done=created");
        Assert.Contains("User created.", list);
        var row = Row(list, name);
        Assert.Contains("Round Trip", row);
        Assert.Contains("<td>person</td>", row);
        Assert.Contains("<td>yes</td>", row);
        var id = await IdOfAsync(api, name);
        Assert.Contains($"/Users/Edit/{id}", row);

        var form = await b.GetStringAsync($"/Users/Edit/{id}");
        Assert.Contains($"value=\"{name}\"", form);
        Assert.Contains("value=\"Round Trip\"", form);
        Assert.Matches("<input type=\"checkbox\" name=\"IsActive\" value=\"true\" checked", form);
        var saved = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["DisplayName"] = "Renamed", ["Kind"] = "shared", ["Expiry"] = "", ["IsActive"] = "true" });
        Assert.Equal("/Users?done=updated", saved.Headers.Location?.OriginalString);
        var stored = await ApiUserAsync(api, id);
        Assert.Equal("shared", stored.GetProperty("kind").GetString());
        Assert.Equal("Renamed", stored.GetProperty("displayName").GetString());

        // an unchecked box disables
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["DisplayName"] = "Renamed", ["Kind"] = "shared", ["Expiry"] = "", ["IsActive"] = "false" });
        Assert.False((await ApiUserAsync(api, id)).GetProperty("isActive").GetBoolean());
        Assert.DoesNotContain("checked", Regex.Match(await b.GetStringAsync($"/Users/Edit/{id}"), "<input type=\"checkbox\"[^>]*>").Value);
        Assert.Contains("<td>no</td>", Row(await b.GetStringAsync("/Users?username=" + name), name));

        var confirm = await b.GetStringAsync($"/Users/Delete/{id}");
        Assert.Contains($"<strong>{name}</strong>", confirm);
        Assert.Contains($"<td>{name}</td>", await b.GetStringAsync("/Users?username=" + name)); // viewing the confirmation deletes nothing
        var deleted = await WebFixture.PostFormAsync(b, $"/Users/Delete/{id}", new());
        Assert.Equal("/Users?done=deleted", deleted.Headers.Location?.OriginalString);
        Assert.DoesNotContain($"<td>{name}</td>", await b.GetStringAsync("/Users?username=" + name));
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/Edit/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Users/Delete/{id}")).StatusCode);
    }

    [Fact]
    public async Task Done_message_is_chosen_by_key_and_never_echoed()
    {
        var b = await _f.SignedInAsync();
        var html = await b.GetStringAsync("/Users?done=" + Uri.EscapeDataString("<b>pwned</b>"));
        Assert.DoesNotContain("pwned", html);
        Assert.DoesNotContain("class=\"notice\"", html);
    }

    [Fact]
    public async Task Unknown_or_malformed_ids_give_the_404_page()
    {
        var b = await _f.SignedInAsync();
        var token = await WebFixture.TokenAsync(b, "/Users/Create");
        var ghost = Guid.NewGuid();
        foreach (var path in new[] { $"/Users/Edit/{ghost}", $"/Users/Delete/{ghost}", "/Users/Edit/not-a-guid", "/Users/Delete/123", "/Users/Edit/" + ghost + "x" })
            Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(path)).StatusCode);
        foreach (var path in new[] { $"/Users/Edit/{ghost}", $"/Users/Delete/{ghost}", "/Users/Edit/not-a-guid" })
        {
            var r = await b.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string>
                { ["Username"] = "x", ["Email"] = "x@example.com", ["Kind"] = "person", ["__RequestVerificationToken"] = token }));
            Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        }
    }

    [Fact]
    public async Task Filters_by_kind_active_and_exact_username()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var p = Unique("flt");
        var (person, test, shared, off) = (p + "-p", p + "-t", p + "-s", p + "-o");
        await ApiCreateAsync(api, person);
        await ApiCreateAsync(api, test, "test");
        await ApiCreateAsync(api, shared, "shared");
        var offId = await ApiCreateAsync(api, off, "shared");
        Assert.True((await api.PatchAsJsonAsync($"/v1/users/{offId}", new { isActive = false })).IsSuccessStatusCode);

        var tests = await b.GetStringAsync("/Users?kind=test");
        Assert.Contains($"<td>{test}</td>", tests);
        Assert.DoesNotContain($"<td>{person}</td>", tests);
        Assert.DoesNotContain($"<td>{shared}</td>", tests);
        Assert.Contains("<option value=\"test\" selected=\"selected\">", tests);

        var inactive = await b.GetStringAsync("/Users?kind=shared&active=false");
        Assert.Contains($"<td>{off}</td>", inactive);
        Assert.DoesNotContain($"<td>{shared}</td>", inactive);
        Assert.Contains("<option value=\"false\" selected=\"selected\">", inactive);
        var active = await b.GetStringAsync("/Users?kind=shared&active=true");
        Assert.Contains($"<td>{shared}</td>", active);
        Assert.DoesNotContain($"<td>{off}</td>", active);

        var exact = await b.GetStringAsync("/Users?username=" + shared);
        Assert.Contains($"<td>{shared}</td>", exact);
        Assert.DoesNotContain($"<td>{person}</td>", exact);
        Assert.Contains($"value=\"{shared}\"", exact);
        Assert.Contains("No users.", await b.GetStringAsync("/Users?username=" + shared[..^1])); // a prefix is not a match
        Assert.Contains("No users.", await b.GetStringAsync("/Users?username=" + shared.ToUpperInvariant() + "x"));

        // unknown filter values are ignored, never forwarded or echoed
        var junk = await b.GetStringAsync("/Users?kind=" + Uri.EscapeDataString("person,test") + "&active=maybe");
        Assert.DoesNotContain("selected=\"selected\"", junk);
        Assert.Contains($"<td>{WebFixture.AdminName}</td>", junk);
        Assert.DoesNotContain("person,test", junk);
        Assert.DoesNotContain("maybe", junk);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users?kind=1&active=2&username=" + Uri.EscapeDataString("a\u0001b‮"))).StatusCode);

        // hostile filter text is encoded where it is shown again
        var hostile = await b.GetStringAsync("/Users?username=" + Uri.EscapeDataString("\"><script>alert(1)</script>"));
        Assert.DoesNotContain("<script>alert", hostile);
        Assert.Contains("&lt;script&gt;", hostile);
    }

    [Fact]
    public async Task Paging_keeps_the_filters_and_a_bad_cursor_returns_to_the_first_page()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var p = Unique("pg");
        for (var i = 0; i < 27; i++) await ApiCreateAsync(api, $"{p}-{i:00}", "shared");

        var first = await b.GetStringAsync("/Users?kind=shared");
        var next = Regex.Match(first, "<a href=\"(/Users\\?[^\"]*cursor=[^\"]+)\">Next page</a>");
        Assert.True(next.Success);
        var href = WebUtility.HtmlDecode(next.Groups[1].Value);
        Assert.Contains("kind=shared", href);
        var second = await b.GetAsync(href);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var secondHtml = await second.Content.ReadAsStringAsync();
        Assert.Contains("<td>shared</td>", secondHtml);
        Assert.DoesNotContain("<td>person</td>", secondHtml);
        var firstNames = Regex.Matches(first, "<tr>\\s*<td>([^<]+)</td>").Select(m => m.Groups[1].Value).ToHashSet();
        var secondNames = Regex.Matches(secondHtml, "<tr>\\s*<td>([^<]+)</td>").Select(m => m.Groups[1].Value).ToList();
        Assert.NotEmpty(secondNames);
        Assert.DoesNotContain(secondNames, firstNames.Contains);

        var bad = await b.GetAsync("/Users?kind=shared&active=true&cursor=" + Uri.EscapeDataString("garbage!!"));
        Assert.Equal(HttpStatusCode.Redirect, bad.StatusCode);
        Assert.Equal("/Users?kind=shared&active=true", bad.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Expiry_is_entered_in_utc_and_empty_means_the_default()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();

        foreach (var (text, offsetSeconds) in new[] { ("T", 0), ("T:ss", 17) })
        {
            var name = Unique("utc");
            var when = DateTime.UtcNow.AddDays(10);
            var typed = text == "T" ? Minute(when) : Minute(when) + ":" + offsetSeconds;
            var r = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = typed });
            Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
            var stored = (await ApiUserAsync(api, await IdOfAsync(api, name))).GetProperty("expiresAt").GetDateTimeOffset();
            Assert.Equal(TimeSpan.Zero, stored.Offset);
            Assert.Equal(DateTime.Parse(typed, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal), stored.UtcDateTime);
            var row = Row(await b.GetStringAsync("/Users?username=" + name), name);
            Assert.Contains(stored.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC", row);
        }

        var dflt = Unique("dflt");
        await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = dflt, ["Email"] = dflt + "@example.com", ["Kind"] = "test", ["Expiry"] = "" });
        var d = (await ApiUserAsync(api, await IdOfAsync(api, dflt))).GetProperty("expiresAt").GetDateTimeOffset();
        Assert.InRange((d - DateTimeOffset.UtcNow).TotalDays, 29.9, 30.1);

        // an expiry typed for a person is not sent
        var person = Unique("pexp");
        var ok = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = person, ["Email"] = person + "@example.com", ["Kind"] = "person", ["Expiry"] = Minute(DateTime.UtcNow.AddDays(3)) });
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Equal(JsonValueKind.Null, (await ApiUserAsync(api, await IdOfAsync(api, person))).GetProperty("expiresAt").ValueKind);
    }

    [Theory]
    [InlineData("tomorrow")]
    [InlineData("2026-13-40T10:00")]
    [InlineData("2030-01-01")]
    [InlineData("2030-01-01T10:00Z")]
    [InlineData("2030-01-01T10:00+02:00")]
    [InlineData("1767225600")]
    [InlineData("2030-01-01T10:00\u0001")]
    public async Task A_bad_expiry_text_is_refused_with_a_fixed_text_and_nothing_is_created(string expiry)
    {
        var b = await _f.SignedInAsync();
        var name = Unique("badx");
        var r = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = expiry });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Equal("Expiry must be a date and time in UTC, like 2026-12-31T23:59.", Alert(html));
        Assert.Empty((await (await ApiAdminAsync()).GetFromJsonAsync<JsonElement>("/v1/users?username=" + name)).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task The_apis_400_texts_for_expiry_and_a_bad_kind_are_shown_on_the_form()
    {
        var b = await _f.SignedInAsync();
        var name = Unique("e400");
        var past = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = Minute(DateTime.UtcNow.AddDays(-1)) });
        Assert.Equal(HttpStatusCode.OK, past.StatusCode);
        Assert.Contains("in the future", Alert(await past.Content.ReadAsStringAsync()));
        var far = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = Minute(DateTime.UtcNow.AddDays(400)) });
        Assert.Contains("at most 365 days", Alert(await far.Content.ReadAsStringAsync()));
        var kept = await far.Content.ReadAsStringAsync();
        Assert.Contains($"value=\"{name}\"", kept); // what was typed stays in the form

        foreach (var kind in new[] { "admin", "0", "person,test", "", "Person" })
        {
            var r = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = kind });
            Assert.Equal("Kind must be person, test or shared.", Alert(await r.Content.ReadAsStringAsync()));
        }

        var bad = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = "Not Valid!", ["Email"] = "nope", ["Kind"] = "person" });
        Assert.Equal(HttpStatusCode.OK, bad.StatusCode);
        var text = Alert(await bad.Content.ReadAsStringAsync());
        Assert.Contains("username", text);
        Assert.Contains("email", text);
        Assert.Empty((await (await ApiAdminAsync()).GetFromJsonAsync<JsonElement>("/v1/users?username=" + name)).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Editing_expiry_extends_it_keeps_it_when_unchanged_and_limits_it()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var name = Unique("ext");
        var id = await ApiCreateAsync(api, name, "test");
        var before = (await ApiUserAsync(api, id)).GetProperty("expiresAt").GetDateTimeOffset();

        var form = await b.GetStringAsync($"/Users/Edit/{id}");
        var shown = Regex.Match(form, "name=\"Expiry\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        Assert.Equal(before.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss"), shown);

        // the field shows whole seconds: saving it unchanged must not move or reject the stored value
        var same = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["DisplayName"] = "same", ["Kind"] = "test", ["Expiry"] = shown, ["IsActive"] = "true" });
        Assert.Equal(HttpStatusCode.Redirect, same.StatusCode);
        Assert.Equal(before, (await ApiUserAsync(api, id)).GetProperty("expiresAt").GetDateTimeOffset());

        var later = Minute(DateTime.UtcNow.AddDays(100));
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = later, ["IsActive"] = "true" });
        Assert.Equal(later, (await ApiUserAsync(api, id)).GetProperty("expiresAt").GetDateTimeOffset().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm"));

        var far = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = Minute(DateTime.UtcNow.AddDays(500)), ["IsActive"] = "true" });
        Assert.Equal(HttpStatusCode.BadRequest, far.StatusCode);
        Assert.Contains("at most 365 days", Alert(await far.Content.ReadAsStringAsync()));
        var past = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = Minute(DateTime.UtcNow.AddDays(-2)), ["IsActive"] = "true" });
        Assert.Contains("in the future", Alert(await past.Content.ReadAsStringAsync()));

        // an empty field keeps the date; turning the user into another kind clears it, a person made a test user gets the default
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = "", ["IsActive"] = "true" });
        Assert.Equal(later, (await ApiUserAsync(api, id)).GetProperty("expiresAt").GetDateTimeOffset().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm"));
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "shared", ["Expiry"] = shown, ["IsActive"] = "true" });
        var u = await ApiUserAsync(api, id);
        Assert.Equal("shared", u.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.Null, u.GetProperty("expiresAt").ValueKind);
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "test", ["Expiry"] = "", ["IsActive"] = "true" });
        Assert.InRange((((await ApiUserAsync(api, id)).GetProperty("expiresAt").GetDateTimeOffset()) - DateTimeOffset.UtcNow).TotalDays, 29.9, 30.1);
    }

    [Fact]
    public async Task An_expired_test_user_is_marked_using_expiresAt()
    {
        using var f = new WebFixture(true);
        var b = await f.SignedInAsync();
        var soon = Unique("soon");
        var later = Unique("late");
        await ApiCreateAsync(await ApiAdminAsync(f), later, "test");
        var r = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = soon, ["Email"] = soon + "@example.com", ["Kind"] = "test", ["Expiry"] = DateTime.UtcNow.AddMinutes(10).ToString("yyyy-MM-dd'T'HH:mm:ss") });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);

        var html = await b.GetStringAsync("/Users?kind=test");
        Assert.DoesNotContain("expired", html);
        f.Time.Advance(TimeSpan.FromMinutes(12));
        html = await b.GetStringAsync("/Users?kind=test");
        Assert.Contains("<span class=\"expired\">expired</span>", Row(html, soon));
        Assert.DoesNotContain("expired", Row(html, later));
        Assert.DoesNotContain("expired", Row(await b.GetStringAsync("/Users"), WebFixture.AdminName)); // persons have no expiry
    }

    [Fact]
    public async Task Hostile_text_is_html_encoded_in_lists_forms_and_errors()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var name = Unique("xss");
        var hostile = "<script>alert(1)</script><img src=x onerror=1>\"'";
        var email = "a\"<b>@example.com";
        var id = await ApiCreateAsync(api, name, displayName: hostile, email: email);

        foreach (var url in new[] { "/Users?username=" + name, $"/Users/Edit/{id}", $"/Users/Delete/{id}" })
        {
            var html = await b.GetStringAsync(url);
            Assert.DoesNotContain("<script>alert", html);
            Assert.DoesNotContain("<img src=x", html);
            Assert.DoesNotContain("<b>@", html);
        }
        Assert.Contains("&lt;script&gt;", await b.GetStringAsync("/Users?username=" + name));

        // sent back through a failing form
        var r = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = hostile, ["Email"] = hostile, ["DisplayName"] = hostile, ["Kind"] = "person", ["Expiry"] = hostile });
        var body = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>alert", body);
        Assert.DoesNotContain("<img src=x", body);
        var e = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = hostile, ["Email"] = hostile, ["DisplayName"] = hostile, ["Kind"] = "person", ["Expiry"] = "" });
        body = await e.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>alert", body);
        Assert.DoesNotContain("<img src=x", body);
    }

    [Fact]
    public async Task Conflicts_from_the_api_are_shown_on_the_form()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var a = Unique("dupa");
        var other = Unique("dupb");
        await ApiCreateAsync(api, a);
        var otherId = await ApiCreateAsync(api, other);

        var dupName = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = a, ["Email"] = "new-" + a + "@example.com", ["Kind"] = "person" });
        Assert.Equal(HttpStatusCode.OK, dupName.StatusCode);
        Assert.Contains("already", Alert(await dupName.Content.ReadAsStringAsync()), StringComparison.OrdinalIgnoreCase);
        var dupMail = await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = "new-" + a, ["Email"] = a + "@example.com", ["Kind"] = "person" });
        Assert.Contains("already", Alert(await dupMail.Content.ReadAsStringAsync()), StringComparison.OrdinalIgnoreCase);
        var dupEdit = await WebFixture.PostFormAsync(b, $"/Users/Edit/{otherId}", new() { ["Username"] = a, ["Email"] = other + "@example.com", ["Kind"] = "person", ["IsActive"] = "true" });
        Assert.Equal(HttpStatusCode.Conflict, dupEdit.StatusCode);
        Assert.Contains("already", Alert(await dupEdit.Content.ReadAsStringAsync()), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(other, (await ApiUserAsync(api, otherId)).GetProperty("username").GetString());
    }

    [Fact]
    public async Task The_only_administrator_cannot_be_demoted_disabled_or_deleted()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var adminId = await IdOfAsync(api, WebFixture.AdminName);
        var fields = () => new Dictionary<string, string> { ["Username"] = WebFixture.AdminName, ["Email"] = "web-admin@example.com", ["Kind"] = "person", ["IsActive"] = "true" };
        var kind = fields();
        kind["Kind"] = "test";
        Assert.Contains("must be a person", Alert(await (await WebFixture.PostFormAsync(b, $"/Users/Edit/{adminId}", kind)).Content.ReadAsStringAsync()));
        var off = fields();
        off["IsActive"] = "false";
        Assert.Contains("without an active administrator", Alert(await (await WebFixture.PostFormAsync(b, $"/Users/Edit/{adminId}", off)).Content.ReadAsStringAsync()));
        var del = await WebFixture.PostFormAsync(b, $"/Users/Delete/{adminId}", new());
        Assert.Equal(HttpStatusCode.Conflict, del.StatusCode);
        Assert.Contains("without an active administrator", Alert(await del.Content.ReadAsStringAsync()));
        // still signed in, nothing changed
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
        var admin = await ApiUserAsync(api, adminId);
        Assert.Equal("person", admin.GetProperty("kind").GetString());
        Assert.True(admin.GetProperty("isActive").GetBoolean());
    }

    // The refresh token the web holds for the session of this username (the sessions are private; read them by reflection).
    private string RefreshTokenOf(string username)
    {
        var sessions = _f.Web.Services.GetRequiredService<WebSessions>();
        var dict = (System.Collections.IDictionary)typeof(WebSessions).GetField("_sessions", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(sessions)!;
        return dict.Values.Cast<WebSession>().Single(x => x.Username == username).Tokens.Refresh;
    }

    [Fact]
    public async Task Disabling_yourself_also_ends_the_api_session()
    {
        var (b, id, name) = await SecondAdminAsync();
        var refresh = RefreshTokenOf(name);
        var f = await LoadedFormAsync(b, id);
        f["IsActive"] = "false";
        Assert.Equal("/Login?ended=1", (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", f, $"/Users/Edit/{id}")).Headers.Location?.OriginalString);
        var r = await _f.Api.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh });
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Deleting_yourself_also_ends_the_api_session()
    {
        var (b, id, name) = await SecondAdminAsync();
        var refresh = RefreshTokenOf(name);
        var r = await WebFixture.PostFormAsync(b, $"/Users/Delete/{id}", new(), $"/Users/Delete/{id}");
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _f.Api.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh })).StatusCode);
    }

    [Fact]
    public async Task A_form_without_the_active_field_leaves_the_user_active_and_unticking_disables()
    {
        var (b, id, name) = await SecondAdminAsync();
        var api = await ApiAdminAsync();
        var other = Unique("act");
        var oid = await ApiCreateAsync(api, other);
        var html = await b.GetStringAsync($"/Users/Edit/{oid}");
        Assert.Matches("<input type=\"hidden\" name=\"IsActive\" value=\"false\">\\s*<input type=\"checkbox\" name=\"IsActive\"", html);
        var handMade = new Dictionary<string, string> { ["Username"] = other, ["Email"] = other + "@example.com", ["DisplayName"] = "x", ["Kind"] = "person" };
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/Edit/{oid}", handMade, $"/Users/Edit/{oid}")).StatusCode);
        Assert.True((await ApiUserAsync(api, oid)).GetProperty("isActive").GetBoolean());
        var unticked = await LoadedFormAsync(b, oid);
        unticked["IsActive"] = "false";
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{oid}", unticked, $"/Users/Edit/{oid}");
        Assert.False((await ApiUserAsync(api, oid)).GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task Another_user_who_takes_the_old_username_is_not_taken_for_you()
    {
        var (b, id, name) = await SecondAdminAsync();
        var api = await ApiAdminAsync();
        var f = await LoadedFormAsync(b, id);
        f["Username"] = name + "r";
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", f, $"/Users/Edit/{id}")).StatusCode);
        var other = await ApiCreateAsync(api, name, email: name + "-x@example.com");
        var html = await b.GetStringAsync($"/Users/Edit/{other}");
        Assert.DoesNotContain("your own account", html);
        Assert.DoesNotContain("your own account", await b.GetStringAsync($"/Users/Delete/{other}"));
        var d = await LoadedFormAsync(b, other);
        d["IsActive"] = "false";
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{other}", d, $"/Users/Edit/{other}");
        Assert.Equal("/Users?done=updated", r.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
    }

    [Fact]
    public async Task An_administrator_who_disables_themselves_lands_on_the_sign_in_page()
    {
        var (b, id, name) = await SecondAdminAsync();
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "person", ["IsActive"] = "false" });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.False((await ApiUserAsync(await ApiAdminAsync(), id)).GetProperty("isActive").GetBoolean());
        var login = await b.GetAsync("/Login?ended=1");
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/Users")).StatusCode);
    }

    [Fact]
    public async Task An_administrator_who_deletes_themselves_lands_on_the_sign_in_page()
    {
        var (b, id, _) = await SecondAdminAsync();
        Assert.Contains("<strong>", await b.GetStringAsync($"/Users/Delete/{id}"));
        var r = await WebFixture.PostFormAsync(b, $"/Users/Delete/{id}", new());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task An_administrator_cannot_demote_themselves_and_stays_signed_in()
    {
        var (b, id, name) = await SecondAdminAsync();
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "shared", ["IsActive"] = "true" });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("must be a person", Alert(await r.Content.ReadAsStringAsync()));
        ForgetAdminCache(_f);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);
    }

    [Fact]
    public async Task Changes_are_audited_under_the_signed_in_admin()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var name = Unique("aud");
        var id = await ApiCreateAsync(api, name);
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", new() { ["Username"] = name, ["Email"] = name + "@example.com", ["Kind"] = "person", ["IsActive"] = "false" });
        await WebFixture.PostFormAsync(b, $"/Users/Delete/{id}", new());
        var admin = (await Repo(_f).ListAsync(username: WebFixture.AdminName, slice: new Gatekeeper.Application.Slice(0, 1))).Single();

        foreach (var action in new[] { "PATCH /v1/users/{id}", "DELETE /v1/users/{id}" })
        {
            var audit = await api.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString(action) + "&limit=200");
            var events = JsonDocument.Parse(audit).RootElement.GetProperty("items").EnumerateArray()
                .Where(e => (e.GetProperty("target").GetString() ?? "").Contains(id.ToString())).ToList();
            var e = Assert.Single(events);
            Assert.Equal(admin.Id.ToString(), e.GetProperty("actor").GetString());
        }

        var create = Unique("auc");
        await WebFixture.PostFormAsync(b, "/Users/Create", new() { ["Username"] = create, ["Email"] = create + "@example.com", ["Kind"] = "shared" });
        var created = JsonDocument.Parse(await api.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("POST /v1/users") + "&limit=5")).RootElement.GetProperty("items")[0];
        Assert.Equal(admin.Id.ToString(), created.GetProperty("actor").GetString());
        Assert.DoesNotContain(create, created.ToString()); // no more than the API records on its own
    }

    [Theory]
    [InlineData("503", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("down", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("500", HttpStatusCode.BadGateway, "could not complete")]
    [InlineData("404", HttpStatusCode.NotFound, "")]
    public async Task Api_outages_on_the_user_pages_get_an_honest_status_without_leaking_detail(string mode, HttpStatusCode expected, string text)
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (!armed || !r.RequestUri!.AbsolutePath.StartsWith("/v1/users")) return null;
            return mode switch
            {
                "503" => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                "down" => throw new HttpRequestException("refused at 10.1.2.3"),
                "404" => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") },
                _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{\"detail\":\"secret-internal\"}") },
            };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var uid = Guid.NewGuid();
        armed = true;
        var create = new Dictionary<string, string> { ["Username"] = "x-user", ["Email"] = "x@example.com", ["Kind"] = "person" };
        var responses = new List<HttpResponseMessage> { await b.GetAsync($"/Users/Delete/{uid}"), await b.GetAsync($"/Users/Edit/{uid}"), await WebFixture.PostFormAsync(b, "/Users/Delete/" + uid, new(), tokenFrom: "/Users/Create") };
        if (mode != "404") responses.Add(await WebFixture.PostFormAsync(b, "/Users/Create", create));
        if (mode != "404") responses.Add(await b.GetAsync("/Users"));
        foreach (var r in responses)
        {
            var body = await r.Content.ReadAsStringAsync();
            Assert.Equal(expected, r.StatusCode);
            Assert.Contains(text, body);
            Assert.DoesNotContain("secret-internal", body);
            Assert.DoesNotContain("10.1.2.3", body);
        }
    }

    // ---- review fixes: only changed fields are sent, self-account handling, fixed error texts ----

    private static string Hidden(string html, string name)
    {
        var m = Regex.Match(html, $"<input type=\"hidden\" name=\"{name}\" value=\"([^\"]*)\"");
        Assert.True(m.Success, "no hidden field " + name);
        return WebUtility.HtmlDecode(m.Groups[1].Value);
    }

    /// <summary>The form as the browser would send it back untouched (visible fields plus the snapshot).</summary>
    private static async Task<Dictionary<string, string>> LoadedFormAsync(HttpClient b, Guid id)
    {
        var html = await b.GetStringAsync($"/Users/Edit/{id}");
        var d = new Dictionary<string, string>();
        foreach (var n in new[] { "Username", "Email", "DisplayName", "Kind", "Expiry" })
            d[n] = n == "Kind" ? Regex.Match(html, "<option value=\"(\\w+)\" selected").Groups[1].Value : WebUtility.HtmlDecode(Regex.Match(html, $"<input name=\"{n}\"[^>]*? value=\"([^\"]*)\"").Groups[1].Value);
        if (Regex.IsMatch(html, "<input type=\"checkbox\" name=\"IsActive\" value=\"true\" checked")) d["IsActive"] = "true"; else d["IsActive"] = "false";
        foreach (var n in new[] { "OrigUsername", "OrigEmail", "OrigDisplayName", "OrigKind", "OrigExpiry", "OrigIsActive" }) d[n] = Hidden(html, n);
        return d;
    }

    private static string Sec(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm:ss");

    [Fact]
    public async Task A_stale_form_does_not_reactivate_a_user_deactivated_meanwhile()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var id = await ApiCreateAsync(api, Unique("stale"));
        var form = await LoadedFormAsync(b, id);
        Assert.Equal("true", form["OrigIsActive"]);
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false })).StatusCode);
        form["DisplayName"] = "Late edit";
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", form, tokenFrom: $"/Users/Edit/{id}");
        Assert.Equal("/Users?done=updated", r.Headers.Location?.OriginalString);
        var stored = await ApiUserAsync(api, id);
        Assert.False(stored.GetProperty("isActive").GetBoolean());
        Assert.Equal("Late edit", stored.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task A_stale_form_does_not_revert_a_shortened_expiry_or_a_changed_kind()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var name = Unique("stexp");
        var created = await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = "", kind = "test", expiresAt = DateTime.UtcNow.AddDays(30) });
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var form = await LoadedFormAsync(b, id);
        var shorter = DateTime.UtcNow.AddDays(3);
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/users/{id}", new { expiresAt = shorter })).StatusCode);
        form["DisplayName"] = "Late edit";
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", form, tokenFrom: $"/Users/Edit/{id}")).StatusCode);
        var stored = await ApiUserAsync(api, id);
        Assert.True(stored.GetProperty("expiresAt").GetDateTime() < DateTime.UtcNow.AddDays(4));
        Assert.Equal("Late edit", stored.GetProperty("displayName").GetString());

        // kind changed meanwhile (test to shared): a stale form that did not touch the kind leaves it
        var form2 = await LoadedFormAsync(b, id);
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/users/{id}", new { kind = "shared" })).StatusCode);
        form2["Email"] = "late-" + name + "@example.com";
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", form2, tokenFrom: $"/Users/Edit/{id}")).StatusCode);
        var after = await ApiUserAsync(api, id);
        Assert.Equal("shared", after.GetProperty("kind").GetString());
        Assert.Equal("late-" + name + "@example.com", after.GetProperty("email").GetString());
    }

    [Fact]
    public async Task An_unchanged_save_sends_no_patch_and_every_real_change_still_works()
    {
        var patches = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (r.Method == HttpMethod.Patch) Interlocked.Increment(ref patches);
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var name = Unique("chg");
        var id = await ApiCreateAsync(api, name, displayName: "First");
        var path = $"/Users/Edit/{id}";

        var form = await LoadedFormAsync(b, id);
        var none = await WebFixture.PostFormAsync(b, path, form);
        Assert.Equal("/Users?done=updated", none.Headers.Location?.OriginalString);
        Assert.Equal(0, patches);

        async Task ChangeAsync(string field, string value)
        {
            var d = await LoadedFormAsync(b, id);
            if (field == "IsActive") d["IsActive"] = "false"; else d[field] = value;
            var before = patches;
            Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, path, d)).StatusCode);
            Assert.Equal(before + 1, patches);
        }

        await ChangeAsync("DisplayName", "Second");
        await ChangeAsync("Email", "new-" + name + "@example.com");
        await ChangeAsync("Username", name + "x");
        await ChangeAsync("IsActive", "");
        await ChangeAsync("Kind", "test");
        var expiry = Sec(DateTime.UtcNow.AddDays(10));
        await ChangeAsync("Expiry", expiry);
        var stored = await ApiUserAsync(api, id);
        Assert.Equal("Second", stored.GetProperty("displayName").GetString());
        Assert.Equal("new-" + name + "@example.com", stored.GetProperty("email").GetString());
        Assert.Equal(name + "x", stored.GetProperty("username").GetString());
        Assert.False(stored.GetProperty("isActive").GetBoolean());
        Assert.Equal("test", stored.GetProperty("kind").GetString());
        Assert.Equal(expiry, Sec(stored.GetProperty("expiresAt").GetDateTime().ToUniversalTime()));
    }

    [Fact]
    public async Task Editing_or_deleting_your_own_account_warns_and_deactivating_or_deleting_it_ends_the_web_session_at_once()
    {
        var (b, id, name) = await SecondAdminAsync();
        Assert.Contains("your own account", await b.GetStringAsync($"/Users/Edit/{id}"));
        Assert.Contains("your own account", await b.GetStringAsync($"/Users/Delete/{id}"));
        var other = await ApiCreateAsync(await ApiAdminAsync(), Unique("oth"));
        Assert.DoesNotContain("your own account", await b.GetStringAsync($"/Users/Edit/{other}"));
        Assert.DoesNotContain("your own account", await b.GetStringAsync($"/Users/Delete/{other}"));

        // a harmless self edit keeps the session
        var form = await LoadedFormAsync(b, id);
        form["DisplayName"] = "Me";
        Assert.Equal("/Users?done=updated", (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", form)).Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Users")).StatusCode);

        var deact = await LoadedFormAsync(b, id);
        deact["IsActive"] = "false";
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", deact);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        var next = await b.GetAsync("/Users");
        Assert.Equal(HttpStatusCode.Redirect, next.StatusCode);
        Assert.Equal("/Login", next.Headers.Location?.OriginalString);

        var (b2, id2, _) = await SecondAdminAsync();
        var del = await WebFixture.PostFormAsync(b2, $"/Users/Delete/{id2}", new());
        Assert.Equal("/Login?ended=1", del.Headers.Location?.OriginalString);
        Assert.Equal("/Login", (await b2.GetAsync("/Users")).Headers.Location?.OriginalString);
        Assert.NotEqual(HttpStatusCode.OK, (await (await ApiAdminAsync()).GetAsync($"/v1/users/{id2}")).StatusCode);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.UnprocessableEntity)]
    public async Task A_client_error_from_the_user_list_gets_a_fixed_message(HttpStatusCode code)
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed && r.RequestUri!.AbsolutePath == "/v1/users" ? new HttpResponseMessage(code) { Content = new StringContent("{\"detail\":\"secret-internal\"}") } : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        armed = true;
        var resp = await b.GetAsync("/Users");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("Could not list users.", Alert(body));
        Assert.DoesNotContain("secret-internal", body);
    }

    [Fact]
    public async Task An_unhandled_api_client_error_shows_a_fixed_text_not_the_api_detail()
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed && r.RequestUri!.AbsolutePath.StartsWith("/v1/users/") ? new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("{\"detail\":\"secret-internal\"}") } : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        armed = true;
        var resp = await b.GetAsync($"/Users/Delete/{Guid.NewGuid()}");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.DoesNotContain("secret-internal", body);
        Assert.Contains("could not complete", body);
        Assert.Contains("href=\"/Users\"", body);
    }
}
