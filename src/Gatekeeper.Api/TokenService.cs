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
    public const string SessionClaim = "sid";

    private readonly ECDsaSecurityKey _key;
    private readonly AuthOptions _options;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public const int MaxRetiredKeys = 5;

    private readonly List<ECDsaSecurityKey> _verificationKeys = [];

    /// <param name="key">The current key: signs new tokens.</param>
    /// <param name="retired">Earlier keys (public halves are enough): published and accepted until the tokens they signed have expired.</param>
    public TokenService(ECDsa key, AuthOptions options, IEnumerable<ECDsa>? retired = null)
    {
        _options = options;
        var p = key.ExportParameters(false);
        Kid = Thumbprint(p);
        _key = new ECDsaSecurityKey(key) { KeyId = Kid };
        PublicKey = new ECDsaSecurityKey(ECDsa.Create(p)) { KeyId = Kid };
        _verificationKeys.Add((ECDsaSecurityKey)PublicKey);
        foreach (var old in retired ?? [])
        {
            var op = old.ExportParameters(false);
            var oldKid = Thumbprint(op);
            if (_verificationKeys.Any(k => k.KeyId == oldKid)) continue; // the current key listed again, or a duplicate
            _verificationKeys.Add(new ECDsaSecurityKey(ECDsa.Create(op)) { KeyId = oldKid });
        }
        if (_verificationKeys.Count - 1 > MaxRetiredKeys)
            throw new ArgumentException($"At most {MaxRetiredKeys} retired keys are supported.");
    }

    public string Kid { get; }
    public string Issuer => _options.Issuer;
    /// <summary>The current key's public half.</summary>
    public SecurityKey PublicKey { get; }
    /// <summary>Every key tokens may be verified with: the current one first, then the retired ones.</summary>
    public IReadOnlyList<SecurityKey> VerificationKeys => _verificationKeys;

    // kid = RFC 7638 thumbprint of the public key, so it is stable and rotation-friendly.
    private static string Thumbprint(ECParameters p)
    {
        if (p.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new ArgumentException("Signing keys must be ECDSA P-256 keys.");
        var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(new ECDsaSecurityKey(ECDsa.Create(p)));
        return Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
    }

    /// <summary>
    /// Reads retired keys from text holding any number of PEM blocks (PUBLIC KEY, PRIVATE KEY or EC PRIVATE KEY); text outside
    /// the blocks (comments) is ignored. Public keys are all that is needed, so a retired private key can be destroyed.
    /// </summary>
    public static List<ECDsa> LoadRetiredKeys(string text)
    {
        var keys = new List<ECDsa>();
        var rest = text.AsSpan();
        while (PemEncoding.TryFind(rest, out var fields))
        {
            var block = rest[fields.Location];
            var ec = ECDsa.Create();
            var label = rest[fields.Label].ToString();
            switch (label)
            {
                case "PUBLIC KEY": ec.ImportFromPem(block); break;
                case "PRIVATE KEY": ec.ImportFromPem(block); break;
                case "EC PRIVATE KEY": ec.ImportFromPem(block); break;
                default: throw new ArgumentException($"Unsupported PEM block '{label}' in the retired keys.");
            }
            keys.Add(ec);
            rest = rest[fields.Location.End..];
        }
        return keys;
    }

    /// <summary>Loads a PEM (PKCS#8 or SEC1) private key.</summary>
    public static ECDsa LoadKey(string pem)
    {
        var ec = ECDsa.Create();
        ec.ImportFromPem(pem);
        return ec;
    }

    public static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <param name="sessionId">Set for tokens that come from a refresh session: becomes the <c>sid</c> claim, so ending the session also ends these tokens where they are checked against the store.</param>
    public (string Token, DateTimeOffset ExpiresAt) Issue(AuthResult auth, DateTimeOffset? now = null, Guid? sessionId = null)
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
                .. sessionId is { } sid ? [new Claim(SessionClaim, sid.ToString())] : Array.Empty<Claim>(),
            ]),
            Claims = new Dictionary<string, object> { [RolesClaim] = auth.Roles.Order(StringComparer.Ordinal).ToArray() },
        };
        return (_handler.CreateToken(descriptor), expires);
    }

    /// <summary>A token for a service identity: sub is the client id, plus the client_id claim (RFC 9068) and the app's roles.</summary>
    public (string Token, DateTimeOffset ExpiresAt) IssueForClient(ClientAuthResult auth, DateTimeOffset? now = null)
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
                new Claim(JwtRegisteredClaimNames.Sub, auth.Client.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("client_id", auth.Client.Name),
            ]),
            Claims = new Dictionary<string, object> { [RolesClaim] = auth.Roles.Order(StringComparer.Ordinal).ToArray() },
        };
        return (_handler.CreateToken(descriptor), expires);
    }

    /// <summary>The public key set as JSON (RFC 7517), current key first. Contains no private parameters.</summary>
    public JsonObject Jwks() => new()
    {
        ["keys"] = new JsonArray(_verificationKeys.Select(k =>
        {
            var p = k.ECDsa.ExportParameters(false);
            return (JsonNode)new JsonObject
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["use"] = "sig",
                ["alg"] = SecurityAlgorithms.EcdsaSha256,
                ["kid"] = k.KeyId,
                ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
                ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
            };
        }).ToArray()),
    };
}
