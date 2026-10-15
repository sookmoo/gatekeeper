using System.Text.Encodings.Web;
using Gatekeeper.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;

// `Gatekeeper.Web healthcheck` is the container HEALTHCHECK (the runtime image has no shell or curl).
if (args is ["healthcheck"]) return await HealthCheck.RunAsync();

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.Limits.MaxRequestBodySize = 64 * 1024; // the largest legitimate form is a few hundred bytes
});

var apiUrl = builder.Configuration["Gatekeeper:ApiUrl"] ?? "http://127.0.0.1:5080";
if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out var apiUri) || (apiUri.Scheme != Uri.UriSchemeHttp && apiUri.Scheme != Uri.UriSchemeHttps))
    return Fail($"Gatekeeper:ApiUrl '{apiUrl}' is not an http(s) URL.");
// Relative request paths resolve against the base address; without a trailing slash its last path segment would be dropped.
if (!apiUri.AbsolutePath.EndsWith('/')) apiUri = new UriBuilder(apiUri) { Path = apiUri.AbsolutePath + "/" }.Uri;
if (!TryFlag("Gatekeeper:AllowPlainApi", out var allowPlainApi) || !TryFlag("Gatekeeper:AllowNonLoopback", out _)
    || !TryFlag("Web:SecureCookies", out var secureCookies))
    return 1;
// Passwords and tokens go to the API: plain http is only for loopback or a private network the operator vouches for.
if (apiUri.Scheme == Uri.UriSchemeHttp && !apiUri.IsLoopback && !allowPlainApi)
    return Fail($"Refusing plain http to {apiUri.Host}: use https:// or set Gatekeeper:AllowPlainApi=true for a private network.");

if (!TryNumber("Web:IdleMinutes", 30, 1, 480, out var idleMinutes) || !TryNumber("Web:AbsoluteHours", 8, 1, 72, out var absoluteHours))
    return 1;

var cookies = new CookieSettings(secureCookies);
builder.Services
    .AddSingleton(TimeProvider.System)
    .AddSingleton(cookies)
    .AddSingleton(new WebOptions { IdleTimeout = TimeSpan.FromMinutes(idleMinutes), AbsoluteTimeout = TimeSpan.FromHours(absoluteHours) })
    .AddSingleton<WebSessions>()
    .AddSingleton<FailureThrottle>()
    .AddHttpClient<GatekeeperApi>(c =>
    {
        c.BaseAddress = apiUri;
        c.Timeout = TimeSpan.FromSeconds(10);
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });

// Antiforgery tokens need no keys that outlive the process: they are only valid for the page they were issued with.
builder.Services.AddSingleton<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(_ => new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider());
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.Name = cookies.CsrfName;
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = secureCookies ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
});

builder.Services.AddAuthentication(SessionAuthHandler.SchemeName).AddScheme<AuthenticationSchemeOptions, SessionAuthHandler>(SessionAuthHandler.SchemeName, null);
builder.Services.AddAuthorizationBuilder().SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
builder.Services.AddRazorPages(o =>
{
    o.Conventions.AllowAnonymousToPage("/Login");
    o.Conventions.AllowAnonymousToPage("/Error");
});

// Behind a TLS proxy, trust it for the real client address and scheme.
var proxies = (builder.Configuration["Web:TrustedProxies"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
if (proxies.Length > 0)
{
    var parsed = new List<System.Net.IPAddress>();
    foreach (var p in proxies)
    {
        // IPAddress.TryParse also accepts shorthand such as "10" (0.0.0.10): insist on a full address.
        if (!(p.Contains('.') || p.Contains(':')) || !System.Net.IPAddress.TryParse(p, out var ip)) return Fail($"Web:TrustedProxies contains an invalid address '{p}'.");
        parsed.Add(ip);
    }
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.ForwardLimit = 1;
        o.KnownProxies.Clear();
        o.KnownIPNetworks.Clear();
        foreach (var ip in parsed) o.KnownProxies.Add(ip);
    });
}

var app = builder.Build();
if (proxies.Length > 0) app.UseForwardedHeaders();

app.Use(async (http, next) =>
{
    // Set when the response starts, so that no later Clear() or error path can leave a response without them.
    http.Response.OnStarting(() =>
    {
        var h = http.Response.Headers;
        // No scripts, no inline styles, no framing, forms only to ourselves.
        h.ContentSecurityPolicy = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
        h.XContentTypeOptions = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["Cross-Origin-Opener-Policy"] = "same-origin";
        h["Cross-Origin-Resource-Policy"] = "same-origin";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        // Everything dynamic can hold names, ids and a session: never cache it (the stylesheet is the exception).
        if (!h.ContainsKey("Cache-Control")) h.CacheControl = "no-store";
        return Task.CompletedTask;
    });
    await next();
});

app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx => ctx.Context.Response.Headers.CacheControl = "public, max-age=3600",
});

// A session the API no longer accepts means "sign in again"; an API that cannot be reached or misbehaves is a plain error page.
app.Use(async (http, next) =>
{
    try
    {
        await next();
    }
    catch (SessionEndedException) when (!http.Response.HasStarted)
    {
        http.Response.StatusCode = StatusCodes.Status303SeeOther;
        http.Response.Headers.Location = "/Login?ended=1";
        SessionCookie.Clear(http);
    }
    catch (ApiException ex) when (!http.Response.HasStarted)
    {
        var (status, retry) = ex.Status switch
        {
            System.Net.HttpStatusCode.TooManyRequests => (StatusCodes.Status429TooManyRequests, true),
            System.Net.HttpStatusCode.Forbidden => (StatusCodes.Status403Forbidden, false),
            System.Net.HttpStatusCode.NotFound => (StatusCodes.Status404NotFound, false),
            System.Net.HttpStatusCode.GatewayTimeout => (StatusCodes.Status504GatewayTimeout, true),
            System.Net.HttpStatusCode.ServiceUnavailable => (StatusCodes.Status503ServiceUnavailable, true),
            _ => (StatusCodes.Status502BadGateway, true),
        };
        http.Response.StatusCode = status;
        http.Response.ContentType = "text/html; charset=utf-8";
        await http.Response.WriteAsync($"<!doctype html><meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"/site.css\"><title>Gatekeeper</title><main><p>{HtmlEncoder.Default.Encode(ex.Message)}</p>{(retry ? "<p><a href=\"/Applications\">Try again</a></p>" : "<p><a href=\"/Applications\">Back to the applications</a></p>")}</main>");
    }
});

// Plain status codes (a missing page, a form that expired) get a readable page instead of an empty body.
app.UseStatusCodePagesWithReExecute("/Error", "?code={0}");
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Text("ok")).AllowAnonymous();
app.MapRazorPages();

// The guard needs the bound addresses, which exist only once the server is running.
await app.StartAsync();
LoopbackGuard.EnsureLoopbackOnly(app);
await app.WaitForShutdownAsync();
return 0;

static int Fail(string message)
{
    Console.Error.WriteLine($"error: {message}");
    return 1;
}

bool TryFlag(string key, out bool value)
{
    value = false;
    if (builder.Configuration[key] is not { Length: > 0 } text) return true;
    if (bool.TryParse(text, out value)) return true;
    Console.Error.WriteLine($"error: {key} must be true or false.");
    return false;
}

bool TryNumber(string key, int fallback, int min, int max, out int value)
{
    value = fallback;
    if (builder.Configuration[key] is not { Length: > 0 } text) return true;
    if (int.TryParse(text, out value) && value >= min && value <= max) return true;
    Console.Error.WriteLine($"error: {key} must be a number between {min} and {max}.");
    return false;
}

public partial class Program;
