using System.Net;
using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

/// <param name="Refresh">Ask for a refresh token (starts a revocable session).</param>
public sealed record LoginRequest(string? Username, string? Password, string? Application, bool? Refresh = null);

public sealed record ClientTokenRequest(string? ClientId, string? ClientSecret);

public sealed record IntrospectRequest(string? Token);

public sealed record RefreshRequest(string? RefreshToken);

public sealed record LoginResponse(
    string AccessToken, string TokenType, int ExpiresIn,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? RefreshToken = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] int? RefreshExpiresIn = null);

public static class AuthEndpoints
{
    // "Authorization: Basic base64(clientId:secret)"; anything else yields nulls, which fail authentication like a wrong secret.
    internal static (string? Id, string? Secret) BasicCredentials(Microsoft.Extensions.Primitives.StringValues header)
    {
        if (header.Count != 1 || header[0] is not { Length: < 1024 } value || !value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return (null, null);
        try
        {
            var text = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(value["Basic ".Length..].Trim()));
            var colon = text.IndexOf(':');
            return colon < 0 ? (null, null) : (text[..colon], text[(colon + 1)..]);
        }
        catch (FormatException)
        {
            return (null, null);
        }
    }

    private const int SlowDownAfterFailures = 20;
    /// <summary>Failures of one dead session's token per window before 429 (and audit rows written for the first of them only).</summary>
    public const int SessionFailuresAllowed = 5;
    private const int SessionFailuresAudited = 3;

    public static void MapAuth(this IEndpointRouteBuilder routes)
    {
        routes.MapGet("/.well-known/jwks.json", (TokenService tokens) => Results.Json(tokens.Jwks()))
            .AllowAnonymous().WithTags("Auth");

        routes.MapPost("/v1/auth/login", async (LoginRequest r, AuthService auth, TokenService tokens, LoginThrottle throttle,
                HttpContext http, AuditRecorder audit, IUserRepository users, SessionService sessions, CancellationToken ct) =>
            {
                var address = (http.Connection.RemoteIpAddress ?? IPAddress.None).ToString();
                if (throttle.IsBlocked(address, r.Username, out var retryAfter))
                {
                    http.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                    return Results.Problem("Too many failed login attempts. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
                }

                var result = await auth.LoginAsync(r.Username, r.Password, r.Application, ct);
                if (result is null)
                {
                    throttle.RecordFailure(address, r.Username);
                    var known = Validation.LooksLikeUsername(r.Username)
                                && (await users.ListAsync(username: r.Username, slice: new Slice(0, 1), ct: ct)).Count > 0;
                    await audit.RecordAsync(http, "anonymous", "auth.login", known ? r.Application : null, false, AuditRecorder.Attempted("username", r.Username, known));
                    // Many failures against one account from many addresses: do not lock the owner out, just slow the guessing.
                    if (throttle.UserFailures(r.Username) >= SlowDownAfterFailures)
                        await Task.Delay(TimeSpan.FromSeconds(2), ct);
                    // One response for every failure: unknown user, wrong password, inactive account, no access to the application.
                    http.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem("Invalid credentials.", statusCode: StatusCodes.Status401Unauthorized);
                }

                // A self-service token (no roles) always comes with a refresh session, so ending the session ends the token. A session-less
                // one could not be revoked before it expires. Asked after the password was verified, so it reveals nothing a success would not.
                if (result.Roles.Count == 0 && r.Refresh != true)
                {
                    await audit.RecordAsync(http, result.User.Id.ToString(), "auth.login", result.App.Name, false, "roles=none; refresh=false");
                    return Results.ValidationProblem(new Dictionary<string, string[]> { ["refresh"] = ["Signing in without roles needs refresh=true."] });
                }

                (Session Session, string Token, AuthResult Auth)? started;
                try
                {
                    started = r.Refresh == true ? await sessions.StartAsync(result, ct) : null;
                }
                catch (BusyException)
                {
                    // The password was verified but the store was too busy to start the session: count it like a failed attempt (so these rows are
                    // bounded by the login throttle) and record it, then answer 503 as for any busy store.
                    throttle.RecordFailure(address, r.Username);
                    await audit.RecordAsync(http, result.User.Id.ToString(), "auth.login", result.App.Name, false, "reason=busy");
                    throw;
                }
                if (r.Refresh == true && started is null)
                {
                    // Deactivated or stripped of the role between the check and the session insert: same answer as any failed login,
                    // and no success is recorded or counted.
                    await audit.RecordAsync(http, result.User.Id.ToString(), "auth.login", result.App.Name, false, "raced");
                    http.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem("Invalid credentials.", statusCode: StatusCodes.Status401Unauthorized);
                }
                throttle.RecordSuccess(address, r.Username);
                await audit.RecordAsync(http, result.User.Id.ToString(), "auth.login", result.App.Name, true, result.Roles.Count == 0 ? "roles=none" : null);
                // With a session, the token carries the roles read after it was stored.
                var (token, expires) = tokens.Issue(started?.Auth ?? result, sessionId: started?.Session.Id);
                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(new LoginResponse(token, "Bearer", (int)(expires - DateTimeOffset.UtcNow).TotalSeconds,
                    started?.Token, started is null ? null : (int)(started.Value.Session.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds));
            })
            .AllowAnonymous().WithTags("Auth");

        // Trade a refresh token for a new access token and a new refresh token (the old one stops working).
        routes.MapPost("/v1/auth/refresh", async (RefreshRequest r, SessionService sessions, TokenService tokens, [FromKeyedServices("refresh")] LoginThrottle throttle,
                [FromKeyedServices("refreshSession")] LoginThrottle sessionThrottle, HttpContext http, AuditRecorder audit, CancellationToken ct) =>
            {
                var address = (http.Connection.RemoteIpAddress ?? IPAddress.None).ToString();
                if (throttle.IsBlocked(address, null, out var retryAfter))
                {
                    http.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                    return Results.Problem("Too many failed attempts. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
                }
                // A token naming a session that already failed too often is refused before the store is touched or an audit row is written.
                var named = SessionService.SessionIdOf(r.RefreshToken);
                var sessionKey = named is { } n ? $"s:{n}" : null;
                if (sessionKey is not null && sessionThrottle.IsBlocked(sessionKey, null, out var sessionWait))
                {
                    http.Response.Headers.RetryAfter = ((int)Math.Ceiling(sessionWait.TotalSeconds)).ToString();
                    return Results.Problem("Too many failed attempts. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
                }

                var result = await sessions.RefreshAsync(r.RefreshToken, ct);
                if (result.Failure is not null || result.Auth is null || result.Session is null || result.Token is null)
                {
                    // Losing a race against a parallel refresh of the same token is not an attack.
                    // Per-address flood counter: unproven tokens and replays. A token that proved its session (hash matched) but whose session is
                    // over or whose user is gone is a stale client, not guessing: it is counted per session instead, a few times, then 429.
                    var stale = result.SessionId is not null && result.Failure is not ("reuse" or "raced");
                    if (result.Failure != "raced" && !stale) throttle.RecordFailure(address, null);
                    var audited = true;
                    if (stale)
                    {
                        sessionThrottle.RecordFailure($"s:{result.SessionId}", null);
                        audited = sessionThrottle.AddressFailures($"s:{result.SessionId}") <= SessionFailuresAudited;
                    }
                    // The session is only named when the caller proved it holds a token of it (the session id itself is public in the sid claim).
                    if (audited)
                        await audit.RecordAsync(http, result.Session?.UserId.ToString() ?? "anonymous", "auth.refresh",
                            result.SessionId?.ToString(), false, result.Failure ?? "invalid");
                    http.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem("Invalid refresh token.", statusCode: StatusCodes.Status401Unauthorized);
                }

                await audit.RecordAsync(http, result.Auth.User.Id.ToString(), "auth.refresh", result.Auth.App.Name, true,
                    $"session={result.Session.Id}" + (result.Auth.Roles.Count == 0 ? "; roles=none" : ""));
                var (token, expires) = tokens.Issue(result.Auth, sessionId: result.Session.Id);
                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(new LoginResponse(token, "Bearer", (int)(expires - DateTimeOffset.UtcNow).TotalSeconds,
                    result.Token, (int)(result.Session.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds));
            })
            .Produces<LoginResponse>().ProducesProblem(StatusCodes.Status401Unauthorized).ProducesProblem(StatusCodes.Status429TooManyRequests)
            .AllowAnonymous().WithTags("Auth");

        // Token introspection for consuming systems. The caller authenticates as a client (HTTP Basic: client id and secret)
        // and can only ask about tokens issued for its own application. Any problem with the caller is one uniform 401.
        routes.MapPost("/v1/auth/introspect", async (Introspector introspector, ClientAuthService clients,
                [FromKeyedServices("client")] LoginThrottle throttle, HttpContext http, AuditRecorder audit, IClientRepository clientRepo, CancellationToken ct) =>
            {
                var address = (http.Connection.RemoteIpAddress ?? IPAddress.None).ToString();
                var (id, secret) = BasicCredentials(http.Request.Headers.Authorization);
                if (throttle.IsBlocked(address, id, out var retryAfter))
                {
                    http.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                    return Results.Problem("Too many failed attempts. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
                }

                if (await clients.AuthenticateAsync(id, secret, ct) is not var (client, app))
                {
                    throttle.RecordFailure(address, id);
                    var known = Validation.LooksLikeUsername(id) && await clientRepo.GetByNameAsync(id!, ct) is not null;
                    await audit.RecordAsync(http, "anonymous", "auth.introspect", null, false, AuditRecorder.Attempted("client", id, known));
                    http.Response.Headers.WWWAuthenticate = "Basic realm=\"gatekeeper\"";
                    return Results.Problem("Invalid credentials.", statusCode: StatusCodes.Status401Unauthorized);
                }

                throttle.RecordSuccess(address, id);
                // The body is read only now, so an unauthenticated caller always gets the 401, never a 400 or 415.
                IntrospectRequest? body;
                try
                {
                    if (!http.Request.HasJsonContentType()) return Results.Problem("Send application/json.", statusCode: StatusCodes.Status415UnsupportedMediaType);
                    body = await http.Request.ReadFromJsonAsync<IntrospectRequest>(ct);
                }
                catch (System.Text.Json.JsonException)
                {
                    return Results.Problem("The request body is not valid JSON.", statusCode: StatusCodes.Status400BadRequest);
                }
                http.Response.Headers.CacheControl = "no-store";
                return Results.Json(await introspector.IntrospectAsync(body?.Token, app, ct));
            })
            .WithDescription("RFC 7662-style. active is false for a token whose user was deactivated or reactivated, whose password was changed or reset, or whose sessions were ended all at once after the token's sign-in began (the user's session cut-off), also for a token without a session. A token carries auth_time (when the sign-in began, in seconds; older tokens are judged by iat); the answer repeats it when the token has it. A sign-in in the same second as a cut-off is treated as before it (sign in again)."
                 + " Guarantee for a token without a session: it is refused when its sign-in was stamped before the change committed, up to the store's clock reading taken as the last write of the change; a sign-in stamped in the few microseconds between that reading and the commit that still verified the old password is not caught and its token lives until exp (a session is always closed completely).")
            .Produces(StatusCodes.Status200OK, contentType: "application/json").ProducesProblem(StatusCodes.Status401Unauthorized).ProducesProblem(StatusCodes.Status429TooManyRequests)
            .AllowAnonymous().WithTags("Auth");

        // Ends the session of a refresh token. Always 204, so it does not reveal whether the token was valid.
        routes.MapPost("/v1/auth/logout", async (RefreshRequest r, SessionService sessions, HttpContext http, AuditRecorder audit, CancellationToken ct) =>
            {
                if (await sessions.LogoutAsync(r.RefreshToken, ct) is { } ended)
                    await audit.RecordAsync(http, ended.UserId.ToString(), "auth.logout", ended.Id.ToString(), true);
                return Results.NoContent();
            })
            .Produces(StatusCodes.Status204NoContent)
            .AllowAnonymous().WithTags("Auth");

        // Client credentials for service identities. Same uniform 401 and throttling as user logins, in a separate counter set.
        routes.MapPost("/v1/auth/client-token", async (ClientTokenRequest r, ClientAuthService auth, TokenService tokens,
                [FromKeyedServices("client")] LoginThrottle throttle, HttpContext http, AuditRecorder audit, IClientRepository clientRepo, CancellationToken ct) =>
            {
                var address = (http.Connection.RemoteIpAddress ?? IPAddress.None).ToString();
                if (throttle.IsBlocked(address, r.ClientId, out var retryAfter))
                {
                    http.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                    return Results.Problem("Too many failed attempts. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
                }

                var result = await auth.LoginAsync(r.ClientId, r.ClientSecret, ct);
                if (result is null)
                {
                    throttle.RecordFailure(address, r.ClientId);
                    var known = Validation.LooksLikeUsername(r.ClientId) && await clientRepo.GetByNameAsync(r.ClientId!, ct) is not null;
                    await audit.RecordAsync(http, "anonymous", "auth.client-token", null, false, AuditRecorder.Attempted("client", r.ClientId, known));
                    http.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem("Invalid credentials.", statusCode: StatusCodes.Status401Unauthorized);
                }

                throttle.RecordSuccess(address, r.ClientId);
                await audit.RecordAsync(http, result.Client.Id.ToString(), "auth.client-token", result.App.Name, true, $"client={result.Client.Name}");
                var (token, expires) = tokens.IssueForClient(result);
                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(new LoginResponse(token, "Bearer", (int)(expires - DateTimeOffset.UtcNow).TotalSeconds));
            })
            .AllowAnonymous().WithTags("Auth");
    }
}
