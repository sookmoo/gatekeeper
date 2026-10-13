using System.Text.Json.Nodes;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeeper.Api;

/// <summary>
/// RFC 7662-style token introspection for the systems that consume Gatekeeper tokens. Offline verification only proves
/// a token was once valid; this also checks the state of the world right now: the user or client is still active, still
/// holds roles in the application (and the roles returned are the current ones), and the refresh session the token came
/// from has not been ended. A caller can only ask about tokens issued for its own application.
/// </summary>
public sealed class Introspector(TokenService tokens, AuthService users, ClientAuthService clients, SessionService sessions)
{
    private const int MaxTokenLength = 8192;
    private static JsonObject Inactive() => new() { ["active"] = false };

    public async Task<JsonObject> IntrospectAsync(string? token, App callerApp, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength) return Inactive();

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = tokens.Issuer,
            ValidateAudience = true,
            ValidAudience = callerApp.Name, // a token for another application is "not active" for this caller
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (_, _, _, _) => tokens.VerificationKeys,
            LifetimeValidator = tokens.LifetimeValidator(TimeSpan.Zero),
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidTypes = [TokenService.TokenType],
            ClockSkew = TimeSpan.Zero,
        });
        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt || !Guid.TryParse(jwt.Subject, out var subject))
            return Inactive();

        AuthResult? user = null;
        ClientAuthResult? client = null;
        if (jwt.TryGetClaim("client_id", out _))
        {
            client = await clients.ResolveAsync(subject, ct);
            if (client is null || client.App.Id != callerApp.Id) return Inactive();
        }
        else
        {
            user = await users.ResolveAsync(subject, callerApp.Id, ct);
            if (user is null) return Inactive();
            if (jwt.TryGetClaim(TokenService.SessionClaim, out var sid))
            {
                if (!Guid.TryParse(sid.Value, out var sessionId) || !await sessions.IsActiveAsync(sessionId, ct))
                    return Inactive();
            }
        }

        var response = new JsonObject
        {
            ["active"] = true,
            ["token_type"] = "Bearer",
            ["iss"] = jwt.Issuer,
            ["aud"] = callerApp.Name,
            ["sub"] = jwt.Subject,
            ["exp"] = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds(),
            ["iat"] = new DateTimeOffset(jwt.IssuedAt).ToUnixTimeSeconds(),
            // The roles as they are now, which may differ from the ones the token was issued with.
            ["roles"] = new JsonArray((user?.Roles ?? client!.Roles).Order(StringComparer.Ordinal).Select(r => (JsonNode)JsonValue.Create(r)!).ToArray()),
        };
        if (jwt.Id is { } jti) response["jti"] = jti;
        if (user is not null) response["preferred_username"] = user.User.Username;
        if (client is not null) response["client_id"] = client.Client.Name;
        if (jwt.TryGetClaim(TokenService.SessionClaim, out var s)) response["sid"] = s.Value;
        return response;
    }
}
