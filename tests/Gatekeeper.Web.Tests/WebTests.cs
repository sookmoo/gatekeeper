extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

public class WebTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public WebTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    [Fact]
    public async Task Pages_need_a_session_and_send_you_to_the_login()
    {
        var b = _f.Browser();
        foreach (var path in new[] { "/", "/Applications", "/Applications/Create", $"/Applications/Edit/{Guid.NewGuid()}", $"/Applications/Delete/{Guid.NewGuid()}" })
        {
            var r = await b.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
            Assert.Equal("/Login", r.Headers.Location?.OriginalString);
        }
        var logout = await b.PostAsync("/Logout", new FormUrlEncodedContent(new Dictionary<string, string>()));
        Assert.NotEqual(HttpStatusCode.OK, logout.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Login")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/health")).StatusCode);
    }

    [Fact]
    public async Task Posting_without_the_antiforgery_token_is_refused()
    {
        var b = _f.Browser();
        var r = await b.PostAsync("/Login", new FormUrlEncodedContent(new Dictionary<string, string> { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword }));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.False(r.Headers.TryGetValues("Set-Cookie", out var cookies) && cookies.Any(c => c.StartsWith("gk_session=")));

        var s = await _f.SignedInAsync();
        var create = await s.PostAsync("/Applications/Create", new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = Unique("csrf") }));
        Assert.Equal(HttpStatusCode.BadRequest, create.StatusCode);
    }

    [Fact]
    public async Task Wrong_credentials_and_non_administrators_get_the_same_message_and_no_session()
    {
        var name = Unique("plain");
        using (var admin = _f.Api.CreateClient())
        {
            var token = await LoginApiAsync(admin);
            admin.DefaultRequestHeaders.Authorization = new("Bearer", token);
            var user = await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com" })).Content.ReadFromJsonAsync<JsonElement>();
            await admin.PutAsJsonAsync($"/v1/users/{user.GetProperty("id").GetString()}/password", new { password = "an ordinary password" });
        }

        string? first = null;
        foreach (var (user, pw) in new[] { (name, "an ordinary password"), (WebFixture.AdminName, "wrong password here"), ("nobody", "whatever password") })
        {
            var b = _f.Browser();
            var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = user, ["Password"] = pw });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var html = await r.Content.ReadAsStringAsync();
            Assert.Contains("Invalid credentials, or not an administrator.", html);
            Assert.DoesNotContain(pw, html);
            Assert.False(r.Headers.TryGetValues("Set-Cookie", out var c) && c.Any(x => x.StartsWith("gk_session=")));
            first ??= html.Length.ToString();
            Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/Applications")).StatusCode);
        }
    }

    private async Task<string> LoginApiAsync(HttpClient c)
    {
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
    }

    [Fact]
    public async Task Sign_in_sets_an_opaque_hardened_cookie_and_tokens_never_reach_the_browser()
    {
        var b = _f.Browser();
        var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Applications", r.Headers.Location?.OriginalString);
        var cookie = r.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("gk_session="));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expires", cookie, StringComparison.OrdinalIgnoreCase); // a session cookie
        Assert.DoesNotContain("eyJ", cookie);   // not a JWT
        Assert.DoesNotContain("gkr_", cookie);  // not a refresh token

        var page = await b.GetAsync("/Applications");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        Assert.DoesNotContain("eyJ", html);
        Assert.DoesNotContain("gkr_", html);
        Assert.Contains(WebFixture.AdminName, html);
    }

    [Fact]
    public async Task Every_response_carries_the_security_headers_and_is_not_cached()
    {
        var b = _f.Browser();
        var r = await b.GetAsync("/Login");
        var csp = r.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("default-src 'none'", csp);
        Assert.DoesNotContain("unsafe", csp);
        Assert.DoesNotContain("script", csp);
        Assert.Equal("nosniff", r.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", r.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
        Assert.False(r.Headers.Contains("Server"));
        var css = await b.GetAsync("/site.css");
        Assert.Equal(HttpStatusCode.OK, css.StatusCode);
        Assert.Contains("max-age", css.Headers.CacheControl?.ToString());
        Assert.DoesNotContain("<script", await b.GetStringAsync("/Login"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Applications_can_be_created_listed_renamed_and_deleted_with_confirmation()
    {
        var b = await _f.SignedInAsync();
        var name = Unique("app");
        var created = await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = name });
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.Equal("/Applications?done=created", created.Headers.Location?.OriginalString);
        var list = await b.GetStringAsync("/Applications?done=created");
        Assert.Contains(name, list);
        Assert.Contains("Application created.", list);

        var dup = await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = name });
        Assert.Equal(HttpStatusCode.OK, dup.StatusCode);
        Assert.Contains("role=\"alert\"", await dup.Content.ReadAsStringAsync());

        var id = System.Text.RegularExpressions.Regex.Match(list, $"<td>{name}</td>\\s*<td><code>([0-9a-f-]{{36}})</code>").Groups[1].Value;
        Assert.NotEmpty(id);

        var newName = Unique("ren");
        var renamed = await WebFixture.PostFormAsync(b, $"/Applications/Edit/{id}", new() { ["Name"] = newName });
        Assert.Equal("/Applications?done=renamed", renamed.Headers.Location?.OriginalString);
        Assert.Contains(newName, await b.GetStringAsync("/Applications"));

        var confirm = await b.GetStringAsync($"/Applications/Delete/{id}");
        Assert.Contains(newName, confirm);
        Assert.Contains(newName, await b.GetStringAsync("/Applications")); // viewing the confirmation deletes nothing
        var deleted = await WebFixture.PostFormAsync(b, $"/Applications/Delete/{id}", new());
        Assert.Equal("/Applications?done=deleted", deleted.Headers.Location?.OriginalString);
        Assert.DoesNotContain(newName, await b.GetStringAsync("/Applications"));
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Applications/Edit/{id}")).StatusCode);
    }

    [Fact]
    public async Task Page_text_is_encoded_and_the_done_message_cannot_be_chosen_by_the_request()
    {
        var b = await _f.SignedInAsync();
        var r = await b.GetStringAsync("/Applications?done=<script>alert(1)</script>");
        Assert.DoesNotContain("<script>alert", r);
        Assert.DoesNotContain("alert(1)", r);
        // an application name with markup is shown as text
        var evil = "a<b>&\"x";
        await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = evil });
        var list = await b.GetStringAsync("/Applications?limit=200");
        Assert.DoesNotContain("<b>", list);
    }

    [Fact]
    public async Task The_reserved_application_cannot_be_renamed_or_deleted_from_the_ui()
    {
        var b = await _f.SignedInAsync();
        var list = await b.GetStringAsync("/Applications");
        Assert.Contains("reserved", list);
        var id = System.Text.RegularExpressions.Regex.Match(list, "<td>gatekeeper</td>\\s*<td><code>([0-9a-f-]{36})</code>").Groups[1].Value;
        var r = await WebFixture.PostFormAsync(b, $"/Applications/Delete/{id}", new());
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("role=\"alert\"", await r.Content.ReadAsStringAsync());
        Assert.Contains("<td>gatekeeper</td>", await b.GetStringAsync("/Applications"));
    }

    [Fact]
    public async Task Sign_out_ends_the_session_here_and_on_the_api()
    {
        var b = await _f.SignedInAsync();
        var sessions = _f.Web.Services.GetRequiredService<WebSessions>();
        var before = sessions.Count;
        var r = await WebFixture.PostFormAsync(b, "/Logout", new(), tokenFrom: "/Applications");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Login", r.Headers.Location?.OriginalString);
        Assert.Contains("gk_session=;", r.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("gk_session=")));
        Assert.Equal(before - 1, sessions.Count);
        Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/Applications")).StatusCode);
    }

    [Fact]
    public async Task A_session_the_api_has_ended_sends_the_browser_back_to_the_login()
    {
        var b = await _f.SignedInAsync();
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode);
        // An administrator ends every session of the web admin on the API.
        var users = _f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();
        var admin = (await users.ListAsync(username: WebFixture.AdminName, slice: new Gatekeeper.Application.Slice(0, 1))).Single();
        await _f.Api.Services.GetRequiredService<Gatekeeper.Application.SessionService>().RevokeAllAsync(admin.Id);
        await Task.Delay(TimeSpan.FromSeconds(11)); // the API caches its administrator check for 10 s
        var r = await b.GetAsync("/Applications");
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.Contains("session ended", await (await b.GetAsync("/Login?ended=1")).Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/Applications")).StatusCode);
    }

    [Fact]
    public async Task Repeated_failed_sign_ins_are_throttled()
    {
        using var f = new WebFixture();
        var b = f.Browser();
        HttpStatusCode last = default;
        for (var i = 0; i < 11; i++)
            last = (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = "nobody", ["Password"] = "wrong password here" })).StatusCode;
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
        // even the right password is refused while blocked
        var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, r.StatusCode);
    }

    [Fact]
    public async Task The_access_token_is_renewed_with_the_refresh_token_when_it_runs_out()
    {
        using var f = new WebFixture(true);
        var b = await f.SignedInAsync();
        f.Time.Advance(TimeSpan.FromSeconds(14 * 60 + 40)); // inside the 30 s renewal margin of the 15 minute token
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode);
        f.Time.Advance(TimeSpan.FromSeconds(14 * 60 + 40));
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode);
        var admin = f.Api.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new("Bearer", await LoginApiAsync(admin));
        var audit = await admin.GetStringAsync("/v1/audit?action=auth.refresh&limit=50");
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(audit, "\"action\":\"auth.refresh\"").Count);
    }

    [Fact]
    public async Task Idle_and_total_session_lifetimes_end_the_session()
    {
        using var f = new WebFixture(true);
        var b = await f.SignedInAsync();
        f.Time.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/Applications")).StatusCode); // idle for 31 minutes

        var c = await f.SignedInAsync();
        for (var i = 0; i < 16; i++)
        {
            f.Time.Advance(TimeSpan.FromMinutes(29));
            Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/Applications")).StatusCode);
        }
        f.Time.Advance(TimeSpan.FromMinutes(29)); // 8 h 13 min since sign-in, though never idle
        Assert.Equal(HttpStatusCode.Redirect, (await c.GetAsync("/Applications")).StatusCode);
    }
}
