extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 6f: non-administrators sign in and see /Account only.</summary>
public class Account6fTests : IClassFixture<WebFixture>
{
    private const string Password = "a plain user password";
    private readonly WebFixture _f;

    public Account6fTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<HttpClient> ApiAdminAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!);
        return c;
    }

    private async Task<(string Name, Guid Id)> NewUserAsync(string? kind = null)
    {
        using var admin = await ApiAdminAsync();
        var name = Unique("plain");
        var user = await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Plain <b>Person</b>", kind })).Content.ReadFromJsonAsync<JsonElement>();
        var id = user.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private async Task<HttpClient> SignInAsync(string name, string password = Password)
    {
        var b = _f.Browser();
        var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = password });
        Assert.True(r.StatusCode == HttpStatusCode.Redirect, "sign-in answered " + (int)r.StatusCode);
        Assert.Equal("/Account", r.Headers.Location?.OriginalString);
        return b;
    }

    private static List<Guid> SessionIds(string html) => Regex.Matches(html, "/Account/Sessions/Revoke/([0-9a-f-]{36})").Select(m => Guid.Parse(m.Groups[1].Value)).ToList();

    [Fact]
    public async Task A_person_without_roles_signs_in_and_lands_on_the_account_page()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        var r = await b.GetAsync("/Account");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Contains(u.Name, html);
        Assert.Contains("Plain &lt;b&gt;Person&lt;/b&gt;", html); // encoded
        Assert.DoesNotContain("<b>Person", html);
        Assert.Contains("(your current session)", html);
        Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/")).StatusCode);
        Assert.Equal("/Account", (await b.GetAsync("/")).Headers.Location?.OriginalString);
        Assert.Equal("/Account", (await b.GetAsync("/Login")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Administrators_still_land_on_the_applications_and_may_open_their_account_too()
    {
        var b = _f.Browser();
        var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal("/Applications", r.Headers.Location?.OriginalString);
        var nav = Regex.Match(await b.GetStringAsync("/Applications"), "<nav>.*?</nav>", RegexOptions.Singleline).Value;
        Assert.Contains("/Users", nav);
        Assert.Contains("/Account", nav);
        var account = await b.GetStringAsync("/Account");
        Assert.Contains(WebFixture.AdminName, account);
    }

    [Fact]
    public async Task The_navigation_of_a_non_administrator_has_only_the_account_link()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        var html = await b.GetStringAsync("/Account");
        var nav = Regex.Match(html, "<nav>.*?</nav>", RegexOptions.Singleline).Value;
        Assert.Contains("href=\"/Account\"", nav);
        foreach (var admin in new[] { "/Applications", "/Users", "/Clients", "/Audit" }) Assert.DoesNotContain(admin, nav);
    }

    [Fact]
    public async Task Failed_sign_ins_say_Invalid_credentials_for_every_reason()
    {
        var u = await NewUserAsync();
        var shared = await NewUserAsync("shared");
        using (var admin = await ApiAdminAsync())
        {
            var disabled = await NewUserAsync();
            Assert.Equal(HttpStatusCode.OK, (await admin.PatchAsJsonAsync($"/v1/users/{disabled.Id}", new { isActive = false })).StatusCode);
            foreach (var (name, pw) in new[] { (u.Name, "wrong password here"), ("nobody-at-all", Password), (disabled.Name, Password), (shared.Name, Password) })
            {
                var r = await WebFixture.PostFormAsync(_f.Browser(), "/Login", new() { ["Username"] = name, ["Password"] = pw });
                Assert.Equal(HttpStatusCode.OK, r.StatusCode);
                Assert.Contains("Invalid credentials.", await r.Content.ReadAsStringAsync());
            }
        }
    }

    [Fact]
    public async Task Every_management_page_answers_403_to_a_non_administrator()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        var open = new[] { "/Account", "/Login", "/Logout", "/Error", "/", "/Index" };
        var pages = _f.Web.Services.GetServices<EndpointDataSource>().SelectMany(d => d.Endpoints).OfType<RouteEndpoint>()
            .Where(e => e.Metadata.GetMetadata<PageActionDescriptor>() is not null)
            .Select(e => "/" + e.RoutePattern.RawText!.TrimStart('/')).Distinct()
            .Where(p => !open.Contains(p) && !p.StartsWith("/Account/", StringComparison.Ordinal)).ToList();
        Assert.True(pages.Count > 25, "the page table looks too small: " + pages.Count);
        var token = await WebFixture.TokenAsync(b, "/Account");
        foreach (var pattern in pages)
        {
            var path = Regex.Replace(pattern, @"\{[^{}:]+(:[^{}]*)?\??\}", _ => Guid.NewGuid().ToString());
            var get = await b.GetAsync(path);
            Assert.True(get.StatusCode == HttpStatusCode.Forbidden, $"GET {path} answered {(int)get.StatusCode}");
            var post = await b.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));
            Assert.True(post.StatusCode == HttpStatusCode.Forbidden, $"POST {path} answered {(int)post.StatusCode}");
            Assert.Contains("You are not allowed to do that.", await get.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task The_account_pages_send_no_script_and_keep_the_security_headers()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        foreach (var path in new[] { "/Account", "/Account/Sessions/RevokeOthers", $"/Account/Sessions/Revoke/{SessionIds(await b.GetStringAsync("/Account")).Single()}" })
        {
            var r = await b.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var html = await r.Content.ReadAsStringAsync();
            Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotMatch(@"<[^>]*\son[a-z]+\s*=", html); // no inline event handlers
            Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
            Assert.Contains("default-src 'none'", r.Headers.GetValues("Content-Security-Policy").Single());
        }
    }

    [Fact]
    public async Task The_account_page_has_no_form_and_a_post_to_it_is_404()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        var token = await WebFixture.TokenAsync(b, "/Account/Sessions/RevokeOthers");
        Assert.Equal(HttpStatusCode.NotFound, (await b.PostAsync("/Account", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }))).StatusCode);
    }

    [Fact]
    public async Task Revoking_another_of_your_sessions_ends_it_and_keeps_this_one()
    {
        var u = await NewUserAsync();
        var b1 = await SignInAsync(u.Name);
        var b2 = await SignInAsync(u.Name);
        var html = await b1.GetStringAsync("/Account");
        var ids = SessionIds(html);
        Assert.Equal(2, ids.Count);
        // the row marked as current has no revoke link of "other"; find the id of the other browser's session
        var currentRow = html.Split("<tr>").Single(row => row.Contains("your current session"));
        var other = ids.Single(i => !currentRow.Contains(i.ToString()));

        var confirm = await b1.GetStringAsync($"/Account/Sessions/Revoke/{other}");
        Assert.DoesNotContain("signs you out", confirm);
        var post = await WebFixture.PostFormAsync(b1, $"/Account/Sessions/Revoke/{other}", new());
        Assert.Equal(HttpStatusCode.Redirect, post.StatusCode);
        Assert.Equal("/Account?done=revoked", post.Headers.Location?.OriginalString);
        Assert.Contains("Session revoked.", await b1.GetStringAsync("/Account?done=revoked"));
        Assert.Single(SessionIds(await b1.GetStringAsync("/Account")));
        Assert.Equal(HttpStatusCode.OK, (await b1.GetAsync("/Account")).StatusCode);
        // the other browser's API session is gone: its next call (the first since sign-in, so nothing is cached) ends in sign-in
        var after = await b2.GetAsync("/Account");
        Assert.Equal(HttpStatusCode.SeeOther, after.StatusCode);
        Assert.Equal("/Login?ended=1", after.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Revoking_the_current_session_ends_the_web_session_cleanly()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        var html = await b.GetStringAsync("/Account");
        var id = SessionIds(html).Single();
        Assert.Contains("Revoking it signs you out at once.", await b.GetStringAsync($"/Account/Sessions/Revoke/{id}"));
        var post = await WebFixture.PostFormAsync(b, $"/Account/Sessions/Revoke/{id}", new());
        Assert.Equal(HttpStatusCode.Redirect, post.StatusCode);
        Assert.Equal("/Login?ended=1", post.Headers.Location?.OriginalString);
        Assert.Equal("/Login", (await b.GetAsync("/Account")).Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Another_users_session_and_an_unknown_id_are_the_same_404()
    {
        var a = await NewUserAsync();
        var other = await NewUserAsync();
        var ba = await SignInAsync(a.Name);
        var bo = await SignInAsync(other.Name);
        var foreign = SessionIds(await bo.GetStringAsync("/Account")).Single();

        var f = await ba.GetAsync($"/Account/Sessions/Revoke/{foreign}");
        var unknown = await ba.GetAsync($"/Account/Sessions/Revoke/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, f.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(ba, $"/Account/Sessions/Revoke/{foreign}", new(), "/Account/Sessions/RevokeOthers")).StatusCode);
        Assert.Single(SessionIds(await bo.GetStringAsync("/Account"))); // untouched
        Assert.Equal(HttpStatusCode.NotFound, (await ba.GetAsync("/Account/Sessions/Revoke/not-a-guid")).StatusCode);
    }

    [Fact]
    public async Task Revoke_others_asks_first_ends_the_other_sessions_and_keeps_this_one()
    {
        var u = await NewUserAsync();
        var b1 = await SignInAsync(u.Name);
        await SignInAsync(u.Name);
        await SignInAsync(u.Name);
        Assert.Contains("Revoke all other sessions", await b1.GetStringAsync("/Account"));
        var confirm = await b1.GetStringAsync("/Account/Sessions/RevokeOthers");
        Assert.Contains("Revoke your 2 other active sessions?", confirm);
        Assert.Contains("Your current session stays", confirm);

        var post = await WebFixture.PostFormAsync(b1, "/Account/Sessions/RevokeOthers", new());
        Assert.Equal(HttpStatusCode.Redirect, post.StatusCode);
        Assert.Equal("/Account?done=revokedothers&n=2", post.Headers.Location?.OriginalString);
        var page = await b1.GetStringAsync(post.Headers.Location!.OriginalString);
        Assert.Contains("2 other sessions revoked.", page);
        Assert.Single(SessionIds(page));
        Assert.DoesNotContain("Revoke all other sessions", page);
        Assert.Contains("You have no other active sessions.", await b1.GetStringAsync("/Account/Sessions/RevokeOthers"));
    }

    [Fact]
    public async Task The_message_keys_in_the_query_string_are_fixed_texts()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        Assert.DoesNotContain("notice", await b.GetStringAsync("/Account?done=%3Cscript%3E"));
        Assert.DoesNotContain("notice", await b.GetStringAsync("/Account?done=revokedothers&n=%3Cb%3E"));
        Assert.DoesNotContain("notice", await b.GetStringAsync("/Account?done=revokedothers&n=-1"));
        Assert.Contains("1 other session revoked.", await b.GetStringAsync("/Account?done=revokedothers&n=1"));
    }

    [Fact]
    public async Task Posts_without_the_antiforgery_token_are_refused()
    {
        var u = await NewUserAsync();
        await SignInAsync(u.Name);
        var b = await SignInAsync(u.Name);
        var id = SessionIds(await b.GetStringAsync("/Account")).First();
        Assert.Equal(HttpStatusCode.BadRequest, (await b.PostAsync($"/Account/Sessions/Revoke/{id}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await b.PostAsync("/Account/Sessions/RevokeOthers", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Equal(2, SessionIds(await b.GetStringAsync("/Account")).Count);
    }

    [Fact]
    public async Task A_shared_account_cannot_sign_in_to_the_web_ui()
    {
        var shared = await NewUserAsync("shared");
        var r = await WebFixture.PostFormAsync(_f.Browser(), "/Login", new() { ["Username"] = shared.Name, ["Password"] = Password });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("Invalid credentials.", await r.Content.ReadAsStringAsync());
    }
}
