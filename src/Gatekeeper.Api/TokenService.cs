using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Gatekeeper.Application;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeeper.Api;

public sealed record AuthOptions
{
    public string Issuer { get; init; } = "gatekeeper";
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// Signs access tokens with an ES256 (ECDSA P-256) key and publishes the public half as a JWKS.
/// Tokens carry the application as <c>aud</c> and the user's roles in that application as <c>roles</c>.
/// </summary>
public sealed class TokenService
{
    public const string TokenType = "at+jwt";
    public const string RolesClaim = "roles";
    public const string UsernameClaim = "preferred_username";

    private readonly ECDsaSecurityKey _key;
    private readonly AuthOptions _options;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public TokenService(ECDsa key, AuthOptions options)
    {
        var p = key.ExportParameters(false);
        if (p.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new ArgumentException("The signing key must be an ECDSA P-256 key.");
        _options = options;
        // kid = RFC 7638 thumbprint of the public key, so it is stable and rotation-friendly.
        var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(new ECDsaSecurityKey(ECDsa.Create(p)));
        Kid = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        _key = new ECDsaSecurityKey(key) { KeyId = Kid };
        PublicKey = new ECDsaSecurityKey(ECDsa.Create(p)) { KeyId = Kid };
    }

    public string Kid { get; }
    public string Issuer => _options.Issuer;
    public SecurityKey PublicKey { get; }

    /// <summary>Loads a PEM (PKCS#8 or SEC1) private key.</summary>
    public static ECDsa LoadKey(string pem)
    {
        var ec = ECDsa.Create();
        ec.ImportFromPem(pem);
        return ec;
    }

    public static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public (string Token, DateTimeOffset ExpiresAt) Issue(AuthResult auth, DateTimeOffset? now = null)
    {
        var issued = now ?? DateTimeOffset.UtcNow;
        var expires = issued + _options.AccessTokenLifetime;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = auth.App.Name,
            IssuedAt = issued.UtcDateTime,
            NotBefore = issued.UtcDateTime,
            Expires = expires.UtcDateTime,
            TokenType = TokenType,
            SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.EcdsaSha256),
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, auth.User.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(UsernameClaim, auth.User.Username),
            ]),
            Claims = new Dictionary<string, object> { [RolesClaim] = auth.Roles.Order(StringComparer.Ordinal).ToArray() },
        };
        return (_handler.CreateToken(descriptor), expires);
    }

    /// <summary>The public key set as JSON (RFC 7517). Contains no private parameters.</summary>
    public JsonObject Jwks()
    {
        var p = ((ECDsaSecurityKey)PublicKey).ECDsa.ExportParameters(false);
        return new JsonObject
        {
            ["keys"] = new JsonArray(new JsonObject
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["use"] = "sig",
                ["alg"] = SecurityAlgorithms.EcdsaSha256,
                ["kid"] = Kid,
                ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
                ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
            }),
        };
    }
}
