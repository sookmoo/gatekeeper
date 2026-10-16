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
    /// <summary>"person", "test" or "shared": lets a consumer treat non-personal accounts differently.</summary>
    public const string KindClaim = "kind";

    private readonly ECDsaSecurityKey _key;
    private readonly AuthOptions _options;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public const int MaxRetiredKeys = 5;

    // The current key (never expires) and the retired ones; a retired key with a retirement stamp stops being trusted once
    // every token it could have signed has expired (the lifetime cap below makes that bound hard).
    private readonly List<(ECDsaSecurityKey Key, DateTimeOffset? RetiredAt)> _keys = [];
    private readonly TimeProvider _time;
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);

    /// <param name="key">The current key: signs new tokens.</param>
    /// <param name="retired">Earlier keys (public halves are enough): published and accepted until the tokens they signed have expired.</param>
    /// <param name="retiredAt">When each retired key was retired (from the <c># retired-at:</c> stamp the rotate script writes). Such keys are dropped automatically once their tokens have expired; unstamped keys stay until removed.</param>
    public TokenService(ECDsa key, AuthOptions options, IEnumerable<ECDsa>? retired = null,
        IReadOnlyDictionary<ECDsa, DateTimeOffset>? retiredAt = null, TimeProvider? time = null)
    {
        _options = options;
        _time = time ?? TimeProvider.System;
        var p = key.ExportParameters(false);
        Kid = Thumbprint(p);
        _key = new ECDsaSecurityKey(key) { KeyId = Kid };
        PublicKey = new ECDsaSecurityKey(ECDsa.Create(p)) { KeyId = Kid };
        _keys.Add(((ECDsaSecurityKey)PublicKey, null));
        foreach (var old in retired ?? [])
        {
            var op = old.ExportParameters(false);
            var oldKid = Thumbprint(op);
            if (_keys.Any(k => k.Key.KeyId == oldKid)) continue; // the current key listed again, or a duplicate
            _keys.Add((new ECDsaSecurityKey(ECDsa.Create(op)) { KeyId = oldKid }, retiredAt is not null && retiredAt.TryGetValue(old, out var at) ? at : null));
        }
        if (_keys.Count - 1 > MaxRetiredKeys)
            throw new ArgumentException($"At most {MaxRetiredKeys} retired keys are supported.");
    }

    public string Kid { get; }
    public string Issuer => _options.Issuer;
    /// <summary>The current key's public half.</summary>
    public SecurityKey PublicKey { get; }
    /// <summary>How long after its retirement a key may still be needed: the longest token lifetime plus clock skew plus a minute.</summary>
    public TimeSpan RetiredKeyLifetime => _options.AccessTokenLifetime + Skew + TimeSpan.FromMinutes(1);
    /// <summary>Every key tokens may be verified with right now: the current one first, then the retired ones that are still needed.</summary>
    public IReadOnlyList<ECDsaSecurityKey> VerificationKeys
    {
        get
        {
            var now = _time.GetUtcNow();
            return _keys.Where(k => k.RetiredAt is not { } at || at + RetiredKeyLifetime > now).Select(k => k.Key).ToList();
        }
    }

    /// <summary>
    /// A lifetime check that also refuses tokens whose validity period is longer than this server ever issues, so a key that
    /// was once trusted cannot be used to mint tokens that outlive its retirement.
    /// </summary>
    public LifetimeValidator LifetimeValidator(TimeSpan skew) => (notBefore, expires, _, _) =>
    {
        if (notBefore is not { } nbf || expires is not { } exp) return false;
        if (exp - nbf > _options.AccessTokenLifetime + TimeSpan.FromSeconds(1)) return false;
        var now = _time.GetUtcNow().UtcDateTime;
        return nbf <= now + skew && exp >= now - skew;
    };

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
    public static List<ECDsa> LoadRetiredKeys(string text) => LoadRetiredKeys(text, out _);

    /// <param name="retiredAt">The <c># retired-at: &lt;ISO time&gt;</c> comment directly before a block, when there is one.</param>
    public static List<ECDsa> LoadRetiredKeys(string text, out IReadOnlyDictionary<ECDsa, DateTimeOffset> retiredAt)
    {
        var keys = new List<ECDsa>();
        var stamps = new Dictionary<ECDsa, DateTimeOffset>();
        var rest = text.AsSpan();
        while (PemEncoding.TryFind(rest, out var fields))
        {
            var before = rest[..fields.Location.Start].ToString();
            RejectStrayText(before);
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
            var stamp = before.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("# retired-at:", StringComparison.Ordinal));
            if (stamp is not null && DateTimeOffset.TryParse(stamp["# retired-at:".Length..].Trim(), System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var at))
                stamps[ec] = at;
            rest = rest[fields.Location.End..];
        }
        RejectStrayText(rest.ToString()); // a truncated block or garbage must not silently turn into "no retired keys"
        retiredAt = stamps;
        return keys;
    }

    // Only blank lines and # comments may sit between PEM blocks.
    private static void RejectStrayText(string text)
    {
        foreach (var line in text.Split('\n'))
            if (line.Trim() is { Length: > 0 } t && !t.StartsWith('#'))
                throw new ArgumentException("The retired keys contain text that is not a complete PEM block or a # comment (is the file truncated?).");
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
        // A test user's token must not outlive the account: consumers check it offline.
        if (auth.User.ExpiresAt is { } accountEnds && accountEnds < expires) expires = accountEnds;
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
                new Claim(KindClaim, auth.User.Kind.ToString().ToLowerInvariant()),
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
        ["keys"] = new JsonArray(VerificationKeys.Select(k =>
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
