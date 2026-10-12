using System.Net;
using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

public sealed record LoginRequest(string? Username, string? Password, string? Application);

public sealed record ClientTokenRequest(string? ClientId, string? ClientSecret);

public sealed record LoginResponse(string AccessToken, string TokenType, int ExpiresIn);

public static class AuthEndpoints
{
    private const int SlowDownAfterFailures = 20;

    public static void MapAuth(this IEndpointRouteBuilder routes)
    {
        routes.MapGet("/.well-known/jwks.json", (TokenService tokens) => Results.Json(tokens.Jwks()))
            .AllowAnonymous().WithTags("Auth");

        routes.MapPost("/v1/auth/login", async (LoginRequest r, AuthService auth, TokenService tokens, LoginThrottle throttle,
                HttpContext http, AuditRecorder audit, CancellationToken ct) =>
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
                    await audit.RecordAsync(http, "anonymous", "auth.login", r.Application, false, $"username={r.Username}");
                    // Many failures against one account from many addresses: do not lock the owner out, just slow the guessing.
                    if (throttle.UserFailures(r.Username) >= SlowDownAfterFailures)
                        await Task.Delay(TimeSpan.FromSeconds(2), ct);
                    // One response for every failure: unknown user, wrong password, inactive account, no access to the application.
                    http.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem("Invalid credentials.", statusCode: StatusCodes.Status401Unauthorized);
                }

                throttle.RecordSuccess(address, r.Username);
                await audit.RecordAsync(http, result.User.Id.ToString(), "auth.login", result.App.Name, true);
                var (token, expires) = tokens.Issue(result);
                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(new LoginResponse(token, "Bearer", (int)(expires - DateTimeOffset.UtcNow).TotalSeconds));
            })
            .AllowAnonymous().WithTags("Auth");

        // Client credentials for service identities. Same uniform 401 and throttling as user logins, in a separate counter set.
        routes.MapPost("/v1/auth/client-token", async (ClientTokenRequest r, ClientAuthService auth, TokenService tokens,
                [FromKeyedServices("client")] LoginThrottle throttle, HttpContext http, AuditRecorder audit, CancellationToken ct) =>
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
                    await audit.RecordAsync(http, "anonymous", "auth.client-token", null, false, $"client={r.ClientId}");
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
