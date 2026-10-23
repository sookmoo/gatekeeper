extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace Gatekeeper.Web.Tests;

/// <summary>Delegates to the real API unless <c>rule</c> answers or throws.</summary>
public sealed class StubHandler(HttpMessageHandler inner, Func<HttpRequestMessage, HttpResponseMessage?> rule) : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
        Task.FromResult(rule(request)) is { Result: { } r } ? Task.FromResult(r) : base.SendAsync(request, ct);
}

public class Qa5aTests
{
    private static WebFixture With(Func<HttpRequestMessage, HttpResponseMessage?> rule, bool fakeTime = false)
    {
        WebFixture? f = null;
        f = new WebFixture(fakeTime, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), rule)));
        return f;
    }

    private static string Name() => $"qa-{Guid.NewGuid():N}"[..16];

    [Fact]
    public async Task Missing_pages_double_deletes_and_expired_forms_show_a_readable_page()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var name = Name();
        await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = name });
        var list = await b.GetStringAsync("/Applications");
        var id = Regex.Match(list, $"<td>{name}</td>\\s*<td><code>([0-9a-f-]{{36}})</code>").Groups[1].Value;
        var (tok, _, ver) = await WebFixture.TokenNonceAndVersionAsync(b, $"/Applications/Delete/{id}");
        var form = () => new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = tok, ["Version"] = ver! });
        Assert.Equal(HttpStatusCode.Redirect, (await b.PostAsync($"/Applications/Delete/{id}", form())).StatusCode);
        var second = await b.PostAsync($"/Applications/Delete/{id}", form()); // a double click
        Assert.Equal(HttpStatusCode.NotFound, second.StatusCode);
        Assert.Contains("already have been deleted", await second.Content.ReadAsStringAsync());

        foreach (var p in new[] { "/Applications/Edit/not-a-guid", "/nothing", $"/Applications/Edit/{Guid.NewGuid()}" })
        {
            var r = await b.GetAsync(p);
            Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
            Assert.Contains("Not found", await r.Content.ReadAsStringAsync());
        }
        var bad = await b.PostAsync("/Applications/Create", new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = "x" }));
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Contains("form may have expired", await bad.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_bad_or_outdated_cursor_starts_over_at_the_first_page()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var r = await b.GetAsync("/Applications?cursor=garbage");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Applications", r.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications?cursor=")).StatusCode);
    }

    [Fact]
    public async Task Odd_names_are_answered_with_the_form_and_a_message_never_a_server_error()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        foreach (var name in new[] { "", "   ", "A", "café", "a<b>&\"x", "http://evil.example/x", new string('a', 100), new string('a', 70_000), "ab\0c" })
        {
            var r = await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = name });
            Assert.True((int)r.StatusCode < 500 || r.StatusCode == HttpStatusCode.RequestEntityTooLarge, $"[{name.Length}] {r.StatusCode}");
        }
    }

    [Fact]
    public async Task Paging_walks_all_pages_without_duplicates()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        for (var i = 0; i < 60; i++) await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = $"pg-{i:D3}" });
        var seen = new List<string>();
        string? url = "/Applications";
        var pages = 0;
        while (url is not null)
        {
            var html = await b.GetStringAsync(url);
            seen.AddRange(Regex.Matches(html, "<td>([^<]+)</td>\\s*<td><code>").Select(m => m.Groups[1].Value));
            var next = Regex.Match(html, "href=\"(/Applications\\?cursor=[^\"]+)\">Next");
            url = next.Success ? WebUtility.HtmlDecode(next.Groups[1].Value) : null;
            pages++;
        }
        Assert.Equal(seen.Count, seen.Distinct().Count());
        Assert.Equal(61, seen.Count); // 60 + the reserved app
        Assert.Equal(3, pages);
    }

    [Theory]
    [InlineData("429", HttpStatusCode.TooManyRequests, "Too many attempts")]
    [InlineData("403", HttpStatusCode.Forbidden, "not allowed")]
    [InlineData("500", HttpStatusCode.BadGateway, "could not complete")]
    [InlineData("html", HttpStatusCode.BadGateway, "could not complete")]
    [InlineData("503", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("down", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("timeout", HttpStatusCode.GatewayTimeout, "did not answer")]
    [InlineData("errors-shape", HttpStatusCode.OK, "")]
    public async Task Api_failures_get_an_honest_status_and_never_leak_what_the_api_said(string mode, HttpStatusCode expected, string text)
    {
        var armed = false;
        using var f = With(r =>
        {
            if (!armed || r.RequestUri!.AbsolutePath != "/v1/applications" || r.Method != HttpMethod.Get) return null;
            return mode switch
            {
                "429" => new HttpResponseMessage(HttpStatusCode.TooManyRequests),
                "403" => new HttpResponseMessage(HttpStatusCode.Forbidden),
                "500" => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{\"title\":\"boom\",\"detail\":\"secret-internal\"}") },
                "503" => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                "html" => new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new StringContent("<html>proxy</html>") },
                "down" => throw new HttpRequestException("refused at 10.1.2.3"),
                "timeout" => throw new TaskCanceledException("timeout"),
                _ => new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"errors\":{\"x\":\"notarray\"}}") },
            };
        });
        var b = await f.SignedInAsync();
        armed = true;
        var r = await b.GetAsync("/Applications");
        var body = await r.Content.ReadAsStringAsync();
        Assert.NotEqual(HttpStatusCode.InternalServerError, r.StatusCode);
        Assert.Contains(text, body);
        if (expected != HttpStatusCode.OK) Assert.Equal(expected, r.StatusCode);
        Assert.DoesNotContain("boom", body);
        Assert.DoesNotContain("secret-internal", body);
        Assert.DoesNotContain("10.1.2.3", body);
        Assert.True(r.Headers.Contains("Content-Security-Policy"));
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task A_session_the_api_refuses_ends_with_headers_and_the_cookie_cleared()
    {
        var armed = false;
        using var f = With(r => armed && r.RequestUri!.AbsolutePath == "/v1/applications" ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : null);
        var b = await f.SignedInAsync();
        armed = true;
        var r = await b.GetAsync("/Applications");
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
        Assert.True(r.Headers.Contains("Content-Security-Policy"));
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
        Assert.Contains(r.Headers.GetValues("Set-Cookie"), c => c.StartsWith("gk_session=;"));
    }

    [Fact]
    public async Task Concurrent_requests_with_an_expired_access_token_refresh_once()
    {
        using var f = new WebFixture(true);
        var b = await f.SignedInAsync();
        f.Time.Advance(TimeSpan.FromSeconds(14 * 60 + 40));
        var rs = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => b.GetAsync("/Applications")));
        Assert.All(rs, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        var admin = f.Api.CreateClient();
        var login = await admin.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        admin.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        var audit = await admin.GetStringAsync("/v1/audit?action=auth.refresh&limit=50");
        Assert.Single(Regex.Matches(audit, "\"action\":\"auth.refresh\""));
    }

    [Fact]
    public async Task Known_limit_guessing_through_the_ui_also_trips_the_apis_pair_throttle()
    {
        // The API sees the UI's address for every browser, so wrong guesses against one account (here spread over "different
        // addresses" by widening the UI's own throttle) block that account at the API too. Other accounts are unaffected.
        using var f = new WebFixture(false, s => s.AddSingleton(new FailureThrottle(TimeProvider.System, 1000, 1000)));
        for (var i = 0; i < 10; i++)
            await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = "wrong password here" });
        var r = await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("Too many attempts", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_reserved_application_cannot_be_renamed_by_a_direct_post()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var list = await b.GetStringAsync("/Applications");
        var id = Regex.Match(list, "<td>gatekeeper</td>\\s*<td><code>([0-9a-f-]{36})</code>").Groups[1].Value;
        var r = await WebFixture.PostFormAsync(b, $"/Applications/Edit/{id}", new() { ["Name"] = "renamed-reserved" });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("role=\"alert\"", await r.Content.ReadAsStringAsync());
        Assert.Contains("<td>gatekeeper</td>", await b.GetStringAsync("/Applications"));
    }

    [Fact]
    public async Task Names_from_the_api_are_html_encoded_in_the_list()
    {
        using var f = With(r => r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath == "/v1/applications"
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new { items = new[] { new { id = Guid.NewGuid(), name = "<img src=x onerror=alert(1)>" } }, nextCursor = "a\"b<c" }) }
            : null);
        var b = await f.SignedInAsync();
        var html = await b.GetStringAsync("/Applications");
        Assert.DoesNotContain("<img", html);
        Assert.Contains("&lt;img", html);
        Assert.DoesNotContain("a\"b<c", html);
    }

    [Fact]
    public async Task A_path_prefix_on_the_api_url_is_kept()
    {
        var paths = new List<string>();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            paths.Add(r.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        })), apiUrl: "http://127.0.0.1/gatekeeper");
        using var _ = f;
        await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = "a", ["Password"] = "b" });
        Assert.Equal(["/gatekeeper/v1/auth/login"], paths);
    }

    [Fact]
    public async Task Signing_in_again_ends_the_previous_session_on_the_api_too()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        var users = f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();
        var admin = (await users.ListAsync(username: WebFixture.AdminName, slice: new Gatekeeper.Application.Slice(0, 1))).Single();
        var sessions = f.Api.Services.GetRequiredService<Gatekeeper.Application.ISessionRepository>();
        Assert.Single(await sessions.ListActiveByUserAsync(admin.Id, DateTimeOffset.UtcNow));
        await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = WebFixture.AdminName, ["Password"] = WebFixture.AdminPassword }, tokenFrom: "/Applications");
        Assert.Single(await sessions.ListActiveByUserAsync(admin.Id, DateTimeOffset.UtcNow)); // one replaced the other
    }
}

public class StartupTests
{
    [Fact]
    public async Task The_loopback_guard_refuses_a_non_loopback_address_once_the_server_is_running()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseSetting("urls", "http://0.0.0.0:0");
        var app = builder.Build();
        await app.StartAsync();
        try
        {
            Assert.Throws<InvalidOperationException>(() => LoopbackGuard.EnsureLoopbackOnly(app));
        }
        finally
        {
            await app.DisposeAsync();
        }

        var local = WebApplication.CreateBuilder();
        local.WebHost.UseSetting("urls", "http://127.0.0.1:0");
        var ok = local.Build();
        await ok.StartAsync();
        try { LoopbackGuard.EnsureLoopbackOnly(ok); } finally { await ok.DisposeAsync(); }

        var allowed = WebApplication.CreateBuilder();
        allowed.WebHost.UseSetting("urls", "http://0.0.0.0:0");
        allowed.Configuration["Gatekeeper:AllowNonLoopback"] = "true";
        var opted = allowed.Build();
        await opted.StartAsync();
        try { LoopbackGuard.EnsureLoopbackOnly(opted); } finally { await opted.DisposeAsync(); }
    }

    [Theory]
    [InlineData("Web:IdleMinutes", "abc")]
    [InlineData("Web:IdleMinutes", "0")]
    [InlineData("Web:AbsoluteHours", "999")]
    [InlineData("Gatekeeper:AllowPlainApi", "maybe")]
    [InlineData("Web:SecureCookies", "yes")]
    [InlineData("Web:TrustedProxies", "10")]
    [InlineData("Web:TrustedProxies", "10.0.0.0/24")]
    [InlineData("Gatekeeper:ApiUrl", "ftp://x")]
    [InlineData("Gatekeeper:ApiUrl", "http://api.example.com")]
    public void Bad_settings_stop_startup_with_a_message_not_a_crash(string key, string value)
    {
        using var f = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseSetting(key, value));
        // the entry point returns an error code before building a host
        Assert.Throws<InvalidOperationException>(() => f.CreateClient());
    }
}
