using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Gatekeeper.Web;

/// <summary>
/// Authentication by the opaque session cookie: the cookie value is looked up in <see cref="WebSessions"/>. The session
/// object is kept in <c>HttpContext.Items</c> for the pages.
/// </summary>
public sealed class SessionAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, WebSessions sessions, CookieSettings cookies)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "gk";
    public const string ItemKey = "gk.session";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (sessions.Find(Request.Cookies[cookies.SessionName]) is not { } session) return Task.FromResult(AuthenticateResult.NoResult());
        Context.Items[ItemKey] = session;
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, session.Username)], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Redirect("/Login");
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}

/// <summary>
/// With <c>Web:SecureCookies=true</c> (behind TLS) the cookies are always <c>Secure</c> and carry the <c>__Host-</c> prefix, which
/// binds them to this exact host (no Domain, path "/") so a sibling host or another port cannot overwrite them.
/// </summary>
public sealed record CookieSettings(bool Secure)
{
    public string SessionName => Secure ? "__Host-gk_session" : "gk_session";
    public string CsrfName => Secure ? "__Host-gk_csrf" : "gk_csrf";
}

public static class SessionCookie
{
    public static string? Read(HttpContext http) => http.Request.Cookies[Settings(http).SessionName];

    public static void Set(HttpContext http, WebSession session) =>
        http.Response.Cookies.Append(Settings(http).SessionName, session.Id, Options(http));

    public static void Clear(HttpContext http) =>
        http.Response.Cookies.Delete(Settings(http).SessionName, Options(http));

    private static CookieSettings Settings(HttpContext http) => http.RequestServices.GetRequiredService<CookieSettings>();

    // A session cookie (no expiry), never readable by scripts and never sent on cross-site requests.
    private static CookieOptions Options(HttpContext http) => new()
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = Settings(http).Secure || http.Request.IsHttps,
        Path = "/",
        IsEssential = true,
    };

    public static WebSession Current(this HttpContext http) =>
        (WebSession)(http.Items[SessionAuthHandler.ItemKey] ?? throw new InvalidOperationException("No signed-in session."));
}
