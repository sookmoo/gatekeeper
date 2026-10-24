extern alias api;

using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Security review of slice 5a: regression-style checks.</summary>
public class Sec5aTests
{
    private sealed class DownHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            throw new HttpRequestException("down");
    }

    private static string? Header(HttpResponseMessage r, string name) =>
        r.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : r.Content.Headers.TryGetValues(name, out var c) ? string.Join(",", c) : null;

    [Fact]
    public async Task Session_ended_redirect_keeps_security_headers_and_clears_the_cookie()
    {
        using var f = new WebFixture();
        var raw = f.Web.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var token = await WebFixture.TokenAsync(raw, "/Login"); // no cookie jar: antiforgery cookie needed too
        var get = await raw.GetAsync("/Login");
        var csrf = get.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("gk_csrf=")).Split(';')[0];
        var html = await get.Content.ReadAsStringAsync();
        var tok = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        var req = new HttpRequestMessage(HttpMethod.Post, "/Login") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword, ["__RequestVerificationToken"] = tok }) };
        req.Headers.Add("Cookie", csrf);
        var login = await raw.SendAsync(req);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var sid = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("gk_session=")).Split(';')[0]["gk_session=".Length..];

        var sessions = f.Web.Services.GetRequiredService<WebSessions>();
        var s = sessions.Find(sid)!;
        s.Tokens = s.Tokens with { Access = WebFixture.FakeAdminToken(), AccessExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10) };

        var r = new HttpRequestMessage(HttpMethod.Get, "/Applications");
        r.Headers.Add("Cookie", "gk_session=" + sid);
        var resp = await raw.SendAsync(r);
        Assert.Equal(HttpStatusCode.SeeOther, resp.StatusCode);
        var missing = new List<string>();
        if (Header(resp, "Cache-Control") != "no-store") missing.Add("Cache-Control");
        if (Header(resp, "Content-Security-Policy") is null) missing.Add("CSP");
        if (Header(resp, "X-Frame-Options") is null) missing.Add("X-Frame-Options");
        if (!(resp.Headers.TryGetValues("Set-Cookie", out var sc) && sc.Any(c => c.StartsWith("gk_session=;")))) missing.Add("Set-Cookie clear");
        Assert.Empty(missing);
    }

    [Fact]
    public async Task Api_down_error_page_keeps_security_headers()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        // from here on the API refuses connections
        using var down = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new DownHandler()));
        var sessions = down.Web.Services.GetRequiredService<WebSessions>();
        var raw = down.Web.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var s0 = sessions.Create("web-admin", new Tokens(WebFixture.FakeAdminToken(), DateTimeOffset.UtcNow.AddMinutes(10), "r", DateTimeOffset.UtcNow.AddHours(1)));
        var req = new HttpRequestMessage(HttpMethod.Get, "/Applications");
        req.Headers.Add("Cookie", "gk_session=" + s0.Id);
        var resp = await raw.SendAsync(req);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        var missing = new List<string>();
        if (Header(resp, "Cache-Control") is null) missing.Add("Cache-Control");
        if (Header(resp, "Content-Security-Policy") is null) missing.Add("CSP");
        if (Header(resp, "X-Frame-Options") is null) missing.Add("X-Frame-Options");
        Assert.Empty(missing);
    }

    [Fact]
    public async Task A_success_on_your_own_account_does_not_reset_guessing_against_another_one()
    {
        using var f = new WebFixture();
        var b = f.Browser();
        HttpStatusCode last = default;
        for (var round = 0; round < 3; round++)
        {
            for (var i = 0; i < 9; i++)
                last = (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = "victim", ["Password"] = "wrong password here" })).StatusCode;
            var ok = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
            Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
            await b.PostAsync("/Logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = await WebFixture.TokenAsync(b, "/Applications") }));
        }
        Assert.Equal(HttpStatusCode.TooManyRequests, last); // the guesses against "victim" added up across the successes
    }

    [Fact]
    public async Task Ten_failures_against_one_account_block_that_account_not_everyone()
    {
        using var f = new WebFixture();
        var attacker = f.Browser();
        for (var i = 0; i < 10; i++)
            await WebFixture.PostFormAsync(attacker, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = "wrong password here" });
        var blocked = await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode); // known limit: from this one address that account waits
        var other = await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = "someone-else", ["Password"] = "wrong password here" });
        Assert.Equal(HttpStatusCode.OK, other.StatusCode); // everyone else can still try
    }

    [Theory]
    [InlineData("HEAD", "/Logout")]
    [InlineData("OPTIONS", "/Applications/Create")]
    [InlineData("TRACE", "/Login")]
    [InlineData("PUT", "/Applications/Create")]
    [InlineData("DELETE", "/Logout")]
    public async Task Odd_methods_do_not_change_state_or_reveal_anything(string method, string path)
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var r = await b.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));
        Assert.NotEqual(HttpStatusCode.NoContent, r.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await f.Browser().GetAsync("/Applications")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode); // still signed in
    }

    [Fact]
    public async Task Query_handler_and_method_override_do_nothing()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var r = await b.GetAsync("/Logout?handler=Post&_method=POST");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var o = new HttpRequestMessage(HttpMethod.Get, "/Logout");
        o.Headers.Add("X-HTTP-Method-Override", "POST");
        await b.SendAsync(o);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode);
    }

    [Fact]
    public async Task Hostile_host_header_is_refused()
    {
        using var f = new WebFixture();
        var c = f.Web.CreateClient();
        var r = new HttpRequestMessage(HttpMethod.Get, "/Login");
        r.Headers.Host = "evil.example";
        Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(r)).StatusCode);
    }
}
