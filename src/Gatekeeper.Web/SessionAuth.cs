using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Gatekeeper.Web;

/// <summary>
/// Authentication by the opaque session cookie: the cookie value is looked up in <see cref="WebSessions"/>. The session
/// object is kept in <c>HttpContext.Items</c> for the pages.
/// </summary>
public sealed class SessionAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, WebSessions sessions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "gk";
    public const string CookieName = "gk_session";
    public const string ItemKey = "gk.session";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (sessions.Find(Request.Cookies[CookieName]) is not { } session) return Task.FromResult(AuthenticateResult.NoResult());
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

public static class SessionCookie
{
    public static void Set(HttpContext http, WebSession session) =>
        http.Response.Cookies.Append(SessionAuthHandler.CookieName, session.Id, Options(http));

    public static void Clear(HttpContext http) =>
        http.Response.Cookies.Delete(SessionAuthHandler.CookieName, Options(http));

    // A session cookie (no expiry), never readable by scripts and never sent on cross-site requests.
    private static CookieOptions Options(HttpContext http) => new()
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = http.Request.IsHttps,
        Path = "/",
        IsEssential = true,
    };

    public static WebSession Current(this HttpContext http) =>
        (WebSession)(http.Items[SessionAuthHandler.ItemKey] ?? throw new InvalidOperationException("No signed-in session."));
}
