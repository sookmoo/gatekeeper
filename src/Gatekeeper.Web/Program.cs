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
// Passwords and tokens go to the API: plain http is only for loopback or a private network the operator vouches for.
if (apiUri.Scheme == Uri.UriSchemeHttp && !apiUri.IsLoopback && !builder.Configuration.GetValue<bool>("Gatekeeper:AllowPlainApi"))
    return Fail($"Refusing plain http to {apiUri.Host}: use https:// or set Gatekeeper:AllowPlainApi=true for a private network.");

var idleMinutes = builder.Configuration.GetValue("Web:IdleMinutes", 30);
var absoluteHours = builder.Configuration.GetValue("Web:AbsoluteHours", 8);
if (idleMinutes is < 1 or > 480) return Fail("Web:IdleMinutes must be between 1 and 480.");
if (absoluteHours is < 1 or > 72) return Fail("Web:AbsoluteHours must be between 1 and 72.");

builder.Services
    .AddSingleton(TimeProvider.System)
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
    o.Cookie.Name = "gk_csrf";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
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
        if (!System.Net.IPAddress.TryParse(p, out var ip)) return Fail($"Web:TrustedProxies contains an invalid address '{p}'.");
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
    var h = http.Response.Headers;
    // No scripts, no inline styles, no framing, forms only to ourselves.
    h.ContentSecurityPolicy = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    h.XContentTypeOptions = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Cross-Origin-Opener-Policy"] = "same-origin";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    // Everything dynamic can hold names, ids and a session: never cache it (the stylesheet below overrides this).
    h.CacheControl = "no-store";
    await next();
});

app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx => ctx.Context.Response.Headers.CacheControl = "public, max-age=3600",
});

// A session the API no longer accepts means "sign in again"; an unreachable API is a plain error page.
app.Use(async (http, next) =>
{
    try
    {
        await next();
    }
    catch (SessionEndedException)
    {
        SessionCookie.Clear(http);
        http.Response.Clear();
        http.Response.StatusCode = StatusCodes.Status303SeeOther;
        http.Response.Headers.Location = "/Login?ended=1";
    }
    catch (ApiException ex) when (!http.Response.HasStarted)
    {
        http.Response.Clear();
        http.Response.StatusCode = ex.Status == System.Net.HttpStatusCode.GatewayTimeout ? StatusCodes.Status504GatewayTimeout : StatusCodes.Status503ServiceUnavailable;
        http.Response.ContentType = "text/html; charset=utf-8";
        await http.Response.WriteAsync($"<!doctype html><meta charset=\"utf-8\"><title>Gatekeeper</title><p>{HtmlEncoder.Default.Encode(ex.Message)}</p><p><a href=\"/\">Try again</a></p>");
    }
});

app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Text("ok")).AllowAnonymous();
app.MapRazorPages();

LoopbackGuard.EnsureLoopbackOnly(app);
await app.RunAsync();
return 0;

static int Fail(string message)
{
    Console.Error.WriteLine($"error: {message}");
    return 1;
}

public partial class Program;
