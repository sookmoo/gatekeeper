extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent QA for slice 5d: gaps beyond Users5dTests.</summary>
public class Users5dQaTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Users5dQaTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];
    private static string Sec(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm:ss");

    private async Task<HttpClient> ApiAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private static async Task<Guid> CreateAsync(HttpClient api, string name, string kind, string? displayName = null)
    {
        var r = await api.PostAsJsonAsync("/v1/users", new { username = name, email = name + "@example.com", displayName = displayName ?? "", kind });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static Task<JsonElement> GetAsync(HttpClient api, Guid id) => api.GetFromJsonAsync<JsonElement>($"/v1/users/{id}");

    private static Dictionary<string, string> Form(string name, string kind, string expiry = "", bool active = true, string display = "")
    {
        var d = new Dictionary<string, string> { ["Username"] = name, ["Email"] = name + "@example.com", ["DisplayName"] = display, ["Kind"] = kind, ["Expiry"] = expiry };
        d["IsActive"] = active ? "true" : "false";
        return d;
    }

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    [Fact]
    public async Task The_365_day_boundary_accepts_just_inside_and_refuses_just_outside()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var inside = Unique("in365");
        var r = await WebFixture.PostFormAsync(b, "/Users/Create", Form(inside, "test", Sec(DateTime.UtcNow.AddDays(365).AddMinutes(-5))));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var outside = Unique("out365");
        var o = await WebFixture.PostFormAsync(b, "/Users/Create", Form(outside, "test", Sec(DateTime.UtcNow.AddDays(365).AddMinutes(5))));
        Assert.Equal(HttpStatusCode.OK, o.StatusCode);
        Assert.Contains("at most 365 days", Alert(await o.Content.ReadAsStringAsync()));
        // past by seconds
        var past = await WebFixture.PostFormAsync(b, "/Users/Create", Form(outside, "test", Sec(DateTime.UtcNow.AddSeconds(-5))));
        Assert.Contains("in the future", Alert(await past.Content.ReadAsStringAsync()));
    }

    [Fact]
    public async Task Expiry_with_fractional_seconds_and_space_separator_is_read_as_utc()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("frac");
        var when = DateTime.UtcNow.AddDays(5);
        var typed = Sec(when) + ".500";
        var r = await WebFixture.PostFormAsync(b, "/Users/Create", Form(name, "test", typed));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var stored = (await GetAsync(api, await IdOf(api, name))).GetProperty("expiresAt").GetDateTimeOffset();
        Assert.Equal(Sec(when), Sec(stored.UtcDateTime));
        var name2 = Unique("sp");
        var r2 = await WebFixture.PostFormAsync(b, "/Users/Create", Form(name2, "test", when.ToString("yyyy-MM-dd HH:mm:ss")));
        Assert.Equal(HttpStatusCode.Redirect, r2.StatusCode);
        Assert.Equal(Sec(when), Sec((await GetAsync(api, await IdOf(api, name2))).GetProperty("expiresAt").GetDateTimeOffset().UtcDateTime));
    }

    private static async Task<Guid> IdOf(HttpClient api, string n) =>
        (await api.GetFromJsonAsync<JsonElement>("/v1/users?username=" + n)).GetProperty("items")[0].GetProperty("id").GetGuid();

    [Fact]
    public async Task An_expired_test_user_can_be_edited_without_touching_the_expiry_and_stays_marked()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("expd");
        var id = await CreateAsync(api, name, "test");
        var repo = _f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();
        var u = (await repo.GetAsync(id))!;
        await repo.UpdateAsync(u with { ExpiresAt = DateTimeOffset.UtcNow.AddHours(-3) });

        var html = await b.GetStringAsync("/Users?username=" + name);
        Assert.Contains("class=\"expired\"", html);
        var form = await b.GetStringAsync($"/Users/Edit/{id}");
        var shown = Regex.Match(form, "name=\"Expiry\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        Assert.NotEmpty(shown);

        // Saving the unchanged past value (display name edit only) must not be rejected as "in the future".
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "test", shown, true, "renamed"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var after = await GetAsync(api, id);
        Assert.Equal("renamed", after.GetProperty("displayName").GetString());
        Assert.True(after.GetProperty("expiresAt").GetDateTimeOffset() < DateTimeOffset.UtcNow);

        // A new past value is refused.
        var bad = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "test", Sec(DateTime.UtcNow.AddHours(-1))));
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }

    [Fact]
    public async Task Kind_transitions_set_and_clear_the_expiry()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("kt");
        var id = await CreateAsync(api, name, "person");
        var explicitExpiry = DateTime.UtcNow.AddDays(40);
        // person -> test with explicit expiry
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "test", Sec(explicitExpiry)))).StatusCode);
        var u = await GetAsync(api, id);
        Assert.Equal("test", u.GetProperty("kind").GetString());
        Assert.Equal(Sec(explicitExpiry), Sec(u.GetProperty("expiresAt").GetDateTimeOffset().UtcDateTime));
        // test -> person clears
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "person", Sec(explicitExpiry)));
        u = await GetAsync(api, id);
        Assert.Equal("person", u.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.Null, u.GetProperty("expiresAt").ValueKind);
        // person -> shared -> test (default 30 days) -> shared
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "shared"));
        Assert.Equal("shared", (await GetAsync(api, id)).GetProperty("kind").GetString());
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "test"));
        Assert.InRange((((await GetAsync(api, id)).GetProperty("expiresAt").GetDateTimeOffset()) - DateTimeOffset.UtcNow).TotalDays, 29.9, 30.1);
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "shared"));
        Assert.Equal(JsonValueKind.Null, (await GetAsync(api, id)).GetProperty("expiresAt").ValueKind);
    }

    [Fact]
    public async Task Edit_form_renders_active_checkbox_state_and_a_roundtrip_without_changes_keeps_everything()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("rt");
        var id = await CreateAsync(api, name, "shared", "Disp");
        await api.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false });

        var form = await b.GetStringAsync($"/Users/Edit/{id}");
        var cb = Regex.Match(form, "<input[^>]*name=\"IsActive\"[^>]*>").Value;
        Assert.DoesNotContain("checked", cb); // inactive user: not checked

        // submit the form exactly as the browser would (checkbox unchecked => field absent)
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "shared", "", false, "Disp"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.False((await GetAsync(api, id)).GetProperty("isActive").GetBoolean());

        // activate
        await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "shared", "", true, "Disp"));
        Assert.True((await GetAsync(api, id)).GetProperty("isActive").GetBoolean());
        form = await b.GetStringAsync($"/Users/Edit/{id}");
        Assert.Contains("checked", Regex.Match(form, "<input[^>]*type=\"checkbox\"[^>]*name=\"IsActive\"[^>]*>").Value);
    }

    [Fact]
    public async Task A_failed_edit_rerenders_the_typed_active_state_not_the_stored_one()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("rr");
        var id = await CreateAsync(api, name, "shared");
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", Form(name, "test", "garbage", false));
        var html = await r.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.DoesNotContain("checked", Regex.Match(html, "<input[^>]*name=\"IsActive\"[^>]*>").Value);
        Assert.True((await GetAsync(api, id)).GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task Concurrent_edits_of_the_same_user_both_succeed_and_leave_a_consistent_user()
    {
        var b1 = await _f.SignedInAsync();
        var b2 = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("cc");
        var id = await CreateAsync(api, name, "shared");
        // both load the form, then both save: last write wins, no error, no corruption
        var f1 = await LoadedAsync(b1, id);
        var f2 = await LoadedAsync(b2, id);
        f1["DisplayName"] = "first";
        f2["DisplayName"] = "second"; f2["IsActive"] = "false";
        var t1 = WebFixture.PostFormAsync(b1, $"/Users/Edit/{id}", f1, $"/Users/Edit/{id}");
        var t2 = WebFixture.PostFormAsync(b2, $"/Users/Edit/{id}", f2, $"/Users/Edit/{id}");
        var rs = await Task.WhenAll(t1, t2);
        Assert.All(rs, r => Assert.Equal(HttpStatusCode.Redirect, r.StatusCode));
        var u = await GetAsync(api, id);
        var disp = u.GetProperty("displayName").GetString();
        var active = u.GetProperty("isActive").GetBoolean();
        // Only changed fields are sent: the second form's deactivation always lands, the display name is whichever saved last.
        Assert.True(disp is "first" or "second", $"state {disp}");
        Assert.False(active, "the deactivation made by the second form must not be undone by the first (stale) one");
    }

    [Fact]
    public async Task Concurrent_edit_and_delete_gives_ok_or_the_404_page_never_a_500()
    {
        var b1 = await _f.SignedInAsync();
        var b2 = await _f.SignedInAsync();
        var api = await ApiAsync();
        var name = Unique("cd");
        var id = await CreateAsync(api, name, "shared");
        var t1 = WebFixture.PostFormAsync(b1, $"/Users/Edit/{id}", Form(name, "shared", "", true, "x"));
        var t2 = WebFixture.PostFormAsync(b2, $"/Users/Delete/{id}", new());
        var rs = await Task.WhenAll(t1, t2);
        Assert.All(rs, r => Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.NotFound, r.StatusCode.ToString()));
        // delete again: 404 page
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b1, $"/Users/Delete/{id}", new(), "/Users")).StatusCode);
    }

    [Fact]
    public async Task Concurrent_creates_of_one_username_yield_one_user_and_one_conflict()
    {
        var b1 = await _f.SignedInAsync();
        var b2 = await _f.SignedInAsync();
        var name = Unique("dupe");
        var rs = await Task.WhenAll(
            WebFixture.PostFormAsync(b1, "/Users/Create", Form(name, "person")),
            WebFixture.PostFormAsync(b2, "/Users/Create", Form(name, "person")));
        Assert.Equal(1, rs.Count(r => r.StatusCode == HttpStatusCode.Redirect));
        Assert.Equal(1, rs.Count(r => r.StatusCode == HttpStatusCode.OK));
    }

    [Theory]
    [InlineData("/Users?kind=bogus&active=maybe")]
    [InlineData("/Users?username=%00")]
    [InlineData("/Users?cursor=")]
    [InlineData("/Users?kind=person&kind=test")]
    [InlineData("/Users?cursor=%FF%FE")]
    public async Task Odd_filters_never_cause_a_server_error(string url)
    {
        var b = await _f.SignedInAsync();
        var r = await b.GetAsync(url);
        Assert.True((int)r.StatusCode < 500, $"{url} -> {(int)r.StatusCode}");
    }

    [Theory]
    [InlineData("/Users/Edit/not-a-guid")]
    [InlineData("/Users/Edit/00000000-0000-0000-0000-000000000000")]
    [InlineData("/Users/Delete/00000000-0000-0000-0000-000000000000")]
    [InlineData("/Users/Edit/")]
    public async Task Bad_ids_are_404(string url)
    {
        var b = await _f.SignedInAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(url)).StatusCode);
    }

    [Fact]
    public async Task Filter_combination_and_paging_with_active_filter_has_no_gaps_or_repeats()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var p = Unique("fp");
        var ids = new List<string>();
        for (var i = 0; i < 30; i++)
        {
            var n = $"{p}-{i:00}";
            var id = await CreateAsync(api, n, i % 2 == 0 ? "shared" : "test");
            if (i % 3 == 0) await api.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false });
            ids.Add(n);
        }
        var seen = new List<string>();
        var url = "/Users?kind=shared&active=true";
        for (var guard = 0; guard < 10 && url is not null; guard++)
        {
            var html = await b.GetStringAsync(url);
            seen.AddRange(Regex.Matches(html, "<tr>\\s*<td>([^<]+)</td>").Select(m => m.Groups[1].Value));
            var next = Regex.Match(html, "<a href=\"(/Users\\?[^\"]*cursor=[^\"]+)\">Next page</a>");
            url = next.Success ? WebUtility.HtmlDecode(next.Groups[1].Value) : null;
        }
        var expected = ids.Where((n, i) => i % 2 == 0 && i % 3 != 0).ToHashSet();
        Assert.Equal(seen.Count, seen.Distinct().Count());
        Assert.True(expected.IsSubsetOf(seen));
        Assert.DoesNotContain(seen, s => s.StartsWith(p) && !expected.Contains(s));
    }

    // ---- re-verification: snapshot tampering and self-matching ----

    private static string Hid(string html, string n) => WebUtility.HtmlDecode(Regex.Match(html, $"<input type=\"hidden\" name=\"{n}\" value=\"([^\"]*)\"").Groups[1].Value);

    private static async Task<Dictionary<string, string>> LoadedAsync(HttpClient b, Guid id)
    {
        var html = await b.GetStringAsync($"/Users/Edit/{id}");
        var d = new Dictionary<string, string>
        {
            ["Username"] = WebUtility.HtmlDecode(Regex.Match(html, "<input name=\"Username\"[^>]*? value=\"([^\"]*)\"").Groups[1].Value),
            ["Email"] = WebUtility.HtmlDecode(Regex.Match(html, "<input name=\"Email\"[^>]*? value=\"([^\"]*)\"").Groups[1].Value),
            ["DisplayName"] = WebUtility.HtmlDecode(Regex.Match(html, "<input name=\"DisplayName\"[^>]*? value=\"([^\"]*)\"").Groups[1].Value),
            ["Kind"] = Regex.Match(html, "<option value=\"(\\w+)\" selected").Groups[1].Value,
            ["Expiry"] = Regex.Match(html, "name=\"Expiry\"[^>]*value=\"([^\"]*)\"").Groups[1].Value,
        };
        if (Regex.IsMatch(html, "name=\"IsActive\" value=\"true\" checked")) d["IsActive"] = "true"; else d["IsActive"] = "false";
        foreach (var n in new[] { "OrigUsername", "OrigEmail", "OrigDisplayName", "OrigKind", "OrigExpiry", "OrigIsActive" }) d[n] = Hid(html, n);
        return d;
    }

    [Fact]
    public async Task Another_users_snapshot_posted_to_this_id_changes_only_what_differs_from_it_and_never_errors()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var a = Unique("sna"); var o = Unique("snb");
        var ida = await CreateAsync(api, a, "person", "Aaa");
        var ido = await CreateAsync(api, o, "shared", "Bbb");
        var form = await LoadedAsync(b, ida);
        var other = await LoadedAsync(b, ido);
        foreach (var k in other.Keys.Where(k => k.StartsWith("Orig"))) form[k] = other[k]; // forged: B's snapshot on A's form
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{ida}", form, tokenFrom: $"/Users/Edit/{ida}");
        Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK, r.StatusCode.ToString());
        var stored = await GetAsync(api, ida);
        Assert.Equal(a, stored.GetProperty("username").GetString());
        Assert.Equal("person", stored.GetProperty("kind").GetString());
        var bs = await GetAsync(api, ido);
        Assert.Equal(o, bs.GetProperty("username").GetString());
        Assert.Equal("Bbb", bs.GetProperty("displayName").GetString());
    }

    [Theory]
    [InlineData("OrigIsActive", "garbage")]
    [InlineData("OrigKind", "admin")]
    [InlineData("OrigExpiry", "not-a-date")]
    [InlineData("OrigUsername", "")]
    [InlineData("OrigEmail", "<script>")]
    public async Task A_garbage_snapshot_value_never_causes_a_server_error_and_never_writes_outside_the_typed_fields(string field, string value)
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var n = Unique("garb");
        var id = await CreateAsync(api, n, "person", "Keep");
        var form = await LoadedAsync(b, id);
        form[field] = value;
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", form, tokenFrom: $"/Users/Edit/{id}");
        Assert.True((int)r.StatusCode < 500, r.StatusCode.ToString());
        var stored = await GetAsync(api, id);
        Assert.Equal("Keep", stored.GetProperty("displayName").GetString());
        Assert.Equal("person", stored.GetProperty("kind").GetString());
        Assert.Equal(n, stored.GetProperty("username").GetString());
    }

    [Fact]
    public async Task Stale_snapshot_with_kind_changed_meanwhile_and_user_intent_to_set_expiry_is_handled_without_a_server_error()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var n = Unique("kx");
        var id = await CreateAsync(api, n, "test");
        var form = await LoadedAsync(b, id);
        Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/users/{id}", new { kind = "person" })).StatusCode);
        form["Expiry"] = Sec(DateTime.UtcNow.AddDays(5));
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", form, tokenFrom: $"/Users/Edit/{id}");
        Assert.True((int)r.StatusCode < 500, r.StatusCode.ToString());
        Assert.Equal("person", (await GetAsync(api, id)).GetProperty("kind").GetString());
    }

    [Fact]
    public async Task Snapshot_is_the_same_data_as_the_visible_form_and_the_page_is_not_cacheable()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAsync();
        var n = Unique("leak");
        var id = await CreateAsync(api, n, "person");
        var resp = await b.GetAsync($"/Users/Edit/{id}");
        Assert.Contains("no-store", resp.Headers.CacheControl?.ToString());
        var html = await resp.Content.ReadAsStringAsync();
        var hidden = Regex.Matches(html, "<input type=\"hidden\" name=\"([^\"]+)\"").Select(m => m.Groups[1].Value).Where(h => h.StartsWith("Orig")).ToArray();
        Assert.Equal(new[] { "OrigUsername", "OrigEmail", "OrigDisplayName", "OrigKind", "OrigExpiry", "OrigIsActive" }, hidden);
        Assert.DoesNotMatch("(?i)hash|secret|type=\"password\"|name=\"Password\"", html);
        Assert.Contains($"<a href=\"/Users/{id}/Password\">Set password</a>", html);
    }

    private async Task<(HttpClient Browser, Guid Id, string Name)> AdminAsync()
    {
        var api = await ApiAsync();
        var name = Unique("adq");
        var id = await CreateAsync(api, name, "person");
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "a long enough password" })).StatusCode);
        var apps = await api.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await api.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        var role = roles.GetProperty("items").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{id}/roles/{role}", null)).StatusCode);
        var b = _f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = "a long enough password" })).StatusCode);
        return (b, id, name);
    }

    [Fact]
    public async Task Self_match_survives_a_rename_of_the_own_account()
    {
        var (b, id, name) = await AdminAsync();
        var f = await LoadedAsync(b, id);
        f["Username"] = name + "z";
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", f, $"/Users/Edit/{id}")).StatusCode);
        // after the rename the page should still know this is the own account
        Assert.Contains("your own account", await b.GetStringAsync($"/Users/Edit/{id}"));
        var d = await LoadedAsync(b, id);
        d["IsActive"] = "false";
        var r = await WebFixture.PostFormAsync(b, $"/Users/Edit/{id}", d, $"/Users/Edit/{id}");
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
    }
}
