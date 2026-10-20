extern alias api;

using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Web.Tests;

/// <summary>A real API (in-memory store) with the web UI in front of it, wired together in-process.</summary>
public sealed class WebFixture : IDisposable
{
    public const string AdminName = "web-admin";
    public const string AdminPassword = "a web admin password";

    public WebApplicationFactory<api::Program> Api { get; }
    public WebApplicationFactory<Program> Web { get; }
    public FakeTimeProvider Time { get; } = new(DateTimeOffset.UtcNow);

    public WebFixture() : this(false)
    {
    }

    internal WebFixture(bool fakeTime, Action<IServiceCollection>? configureWeb = null, string? apiUrl = null, bool secureCookies = false)
    {
        Api = new WebApplicationFactory<api::Program>();
        api::Gatekeeper.Api.Bootstrap.CreateAdminAsync(Api.Services, AdminName, "web-admin@example.com", AdminPassword).GetAwaiter().GetResult();
        Web = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            if (apiUrl is not null) b.UseSetting("Gatekeeper:ApiUrl", apiUrl);
            if (secureCookies) b.UseSetting("Web:SecureCookies", "true");
            b.ConfigureServices(s =>
        {
            // The production client times out after 10 s; on a loaded machine Argon2 logins can exceed that and
            // the login page then answers 200 with a timeout message. Tests must not depend on wall-clock speed.
            s.AddHttpClient<GatekeeperApi>().ConfigureHttpClient(c => c.Timeout = TimeSpan.FromMinutes(5)).ConfigurePrimaryHttpMessageHandler(() => Api.Server.CreateHandler());
            if (fakeTime) s.AddSingleton<TimeProvider>(Time);
            configureWeb?.Invoke(s);
        });
        });
    }

    /// <summary>A browser: keeps cookies, never follows redirects (so they can be asserted).</summary>
    public HttpClient Browser() => Web.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    public static async Task<string> TokenAsync(HttpClient browser, string path) => (await TokenAndNonceAsync(browser, path)).Token;

    /// <summary>The antiforgery token and, on forms that have one, the one-time "Nonce" of the page at <paramref name="path"/> (one GET).</summary>
    public static async Task<(string Token, string? Nonce)> TokenAndNonceAsync(HttpClient browser, string path)
    {
        var html = await browser.GetStringAsync(path);
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(m.Success, "no antiforgery token on " + path);
        var n = Regex.Match(html, "name=\"Nonce\"[^>]*value=\"([^\"]+)\"");
        return (WebUtility.HtmlDecode(m.Groups[1].Value), n.Success ? WebUtility.HtmlDecode(n.Groups[1].Value) : null);
    }

    /// <summary>Submits a form of the page at <paramref name="path"/> with a valid antiforgery token.</summary>
    public static async Task<HttpResponseMessage> PostFormAsync(HttpClient browser, string path, Dictionary<string, string> fields, string? tokenFrom = null)
    {
        var (token, nonce) = await TokenAndNonceAsync(browser, tokenFrom ?? path);
        fields["__RequestVerificationToken"] = token;
        if (nonce is not null && !fields.ContainsKey("Nonce")) fields["Nonce"] = nonce; // what the browser would send back from the form
        return await browser.PostAsync(path, new FormUrlEncodedContent(fields));
    }

    public async Task<HttpClient> SignedInAsync()
    {
        var b = Browser();
        var r = await PostFormAsync(b, "/Login", new() { ["Username"] = AdminName, ["Password"] = AdminPassword });
        Assert.True(r.StatusCode == HttpStatusCode.Redirect, "sign-in answered " + (int)r.StatusCode + ": " + Regex.Match(await r.Content.ReadAsStringAsync(), "class=\"error\"[^>]*>([^<]*)").Groups[1].Value);
        return b;
    }

    public void Dispose()
    {
        Web.Dispose();
        Api.Dispose();
    }
}
