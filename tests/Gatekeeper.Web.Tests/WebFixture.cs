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

    internal WebFixture(bool fakeTime, Action<IServiceCollection>? configureWeb = null)
    {
        Api = new WebApplicationFactory<api::Program>();
        api::Gatekeeper.Api.Bootstrap.CreateAdminAsync(Api.Services, AdminName, "web-admin@example.com", AdminPassword).GetAwaiter().GetResult();
        Web = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => Api.Server.CreateHandler());
            if (fakeTime) s.AddSingleton<TimeProvider>(Time);
            configureWeb?.Invoke(s);
        }));
    }

    /// <summary>A browser: keeps cookies, never follows redirects (so they can be asserted).</summary>
    public HttpClient Browser() => Web.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    public static async Task<string> TokenAsync(HttpClient browser, string path)
    {
        var html = await browser.GetStringAsync(path);
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(m.Success, "no antiforgery token on " + path);
        return WebUtility.HtmlDecode(m.Groups[1].Value);
    }

    /// <summary>Submits a form of the page at <paramref name="path"/> with a valid antiforgery token.</summary>
    public static async Task<HttpResponseMessage> PostFormAsync(HttpClient browser, string path, Dictionary<string, string> fields, string? tokenFrom = null)
    {
        fields["__RequestVerificationToken"] = await TokenAsync(browser, tokenFrom ?? path);
        return await browser.PostAsync(path, new FormUrlEncodedContent(fields));
    }

    public async Task<HttpClient> SignedInAsync()
    {
        var b = Browser();
        var r = await PostFormAsync(b, "/Login", new() { ["Username"] = AdminName, ["Password"] = AdminPassword });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        return b;
    }

    public void Dispose()
    {
        Web.Dispose();
        Api.Dispose();
    }
}
