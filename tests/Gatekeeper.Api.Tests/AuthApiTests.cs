using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeeper.Api.Tests;

public class AuthApiTests
{
    private const string Password = "correct horse battery";

    private static WebApplicationFactory<Program> NewFactory() => new WebApplicationFactory<Program>();

    private static async Task<Guid> Post(HttpClient c, string url, object body)
    {
        var r = await c.PostAsJsonAsync(url, body);
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    /// <summary>Creates app+role+user with a password and assigns the role. Returns the username.</summary>
    private static async Task<string> Seed(HttpClient admin, string app, string role, bool active = true, bool assign = true, string? password = Password)
    {
        var appId = await Post(admin, "/v1/applications", new { name = app });
        var roleId = await Post(admin, $"/v1/applications/{appId}/roles", new { name = role });
        return await SeedUser(admin, roleId, active, assign, password);
    }

    private static async Task<string> SeedUser(HttpClient admin, Guid? roleId, bool active = true, bool assign = true, string? password = Password)
    {
        var name = $"u{Guid.NewGuid():N}"[..12];
        var userId = await Post(admin, "/v1/users", new { username = name, email = $"{name}@example.com", isActive = active });
        if (password is not null)
            Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password })).StatusCode);
        if (assign && roleId is not null)
            Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        return name;
    }

    private static Task<HttpResponseMessage> Login(HttpClient c, string? user, string? password, string? app) =>
        c.PostAsJsonAsync("/v1/auth/login", new { username = user, password, application = app });

    [Fact]
    public async Task Management_api_and_readiness_require_a_token_but_health_and_jwks_are_public()
    {
        using var f = NewFactory();
        var anon = f.CreateClient();
        var r = await anon.GetAsync("/v1/applications");
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/users", new { username = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await f.CreateAdminClient().GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.GetAsync("/.well-known/jwks.json")).StatusCode);
    }

    [Fact]
    public async Task Jwks_publishes_only_the_public_key()
    {
        using var f = NewFactory();
        var text = await f.CreateClient().GetStringAsync("/.well-known/jwks.json");
        var key = JsonDocument.Parse(text).RootElement.GetProperty("keys")[0];
        Assert.Equal("EC", key.GetProperty("kty").GetString());
        Assert.Equal("P-256", key.GetProperty("crv").GetString());
        Assert.Equal("ES256", key.GetProperty("alg").GetString());
        Assert.False(key.TryGetProperty("d", out _));
    }

    [Fact]
    public async Task Login_issues_a_token_a_consumer_can_verify_with_the_jwks()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var user = await Seed(admin, "shop", "buyer");
        // a second role in another app must not leak into the token
        var other = await Post(admin, "/v1/applications", new { name = "other" });
        var otherRole = await Post(admin, $"/v1/applications/{other}/roles", new { name = "x" });
        var uid = (await (await admin.GetAsync($"/v1/users?username={user}")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("items")[0].GetProperty("id").GetGuid();
        await admin.PutAsync($"/v1/users/{uid}/roles/{otherRole}", null);

        var r = await Login(f.CreateClient(), user, Password, "SHOP");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Bearer", body.GetProperty("tokenType").GetString());
        Assert.InRange(body.GetProperty("expiresIn").GetInt32(), 800, 900);
        var token = body.GetProperty("accessToken").GetString()!;

        // Consumer side: fetch the JWKS, validate offline.
        var jwks = new JsonWebKeySet(await f.CreateClient().GetStringAsync("/.well-known/jwks.json"));
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "gatekeeper", ValidAudience = "shop", IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = ["ES256"], ValidTypes = ["at+jwt"],
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        var jwt = (JsonWebToken)result.SecurityToken;
        Assert.Equal(uid.ToString(), jwt.Subject);
        Assert.Equal(user, jwt.GetClaim("preferred_username").Value);
        Assert.Equal(["buyer"], jwt.GetPayloadValue<string[]>("roles"));
        Assert.Equal("ES256", jwt.Alg);
        Assert.False(string.IsNullOrEmpty(jwt.GetClaim("jti").Value));
    }

    [Fact]
    public async Task Every_login_failure_looks_identical()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var good = await Seed(admin, "shop", "buyer");
        var inactive = await Seed(admin, "shop2", "buyer", active: false);
        var unassigned = await Seed(admin, "shop3", "buyer", assign: false);
        var noPassword = await Seed(admin, "shop4", "buyer", password: null);
        var c = f.CreateClient();

        var attempts = new (string?, string?, string?)[]
        {
            (good, "wrong password here", "shop"), ("nobody", Password, "shop"), (good, Password, "no-such-app"),
            (good, Password, "shop2"), (inactive, Password, "shop2"), (unassigned, Password, "shop3"), (noPassword, Password, "shop4"),
            (null, null, null), ("", "", ""), (good, "short", "shop"), (new string('a', 5000), Password, "shop"), ("bad\u0000name", Password, "shop"),
        };
        var bodies = new HashSet<string>();
        foreach (var (u, p, a) in attempts)
        {
            var r = await Login(c, u, p, a);
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.Equal("Bearer", r.Headers.WwwAuthenticate.ToString());
            var json = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;
            bodies.Add($"{json.GetProperty("title")}|{json.GetProperty("detail")}|{json.GetProperty("status")}");
        }
        Assert.Single(bodies);
    }

    [Fact]
    public async Task Admin_logs_in_and_manages_but_other_apps_tokens_cannot()
    {
        using var f = NewFactory();
        var seed = f.CreateAdminClient();
        var adminName = TestAuth.AdminName;
        await Seed(seed, "shop", "buyer");
        var shopUser = (await Seed(seed, "shop-b", "buyer"));

        var anon = f.CreateClient();
        var login = await Login(anon, adminName, TestAuth.AdminPassword, "gatekeeper");
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        var real = f.CreateClient();
        real.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.OK, (await real.GetAsync("/v1/applications")).StatusCode);

        // A valid token for another application is not a management token.
        var shopToken = (await (await Login(anon, shopUser, Password, "shop-b")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        var other = f.CreateClient();
        other.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", shopToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/v1/applications")).StatusCode);
    }

    [Fact]
    public async Task Admin_audience_without_the_admin_role_is_forbidden()
    {
        using var f = NewFactory();
        var c = f.CreateClient();
        // A real administrator whose token (somehow) lacks the admin role claim: the policy refuses it.
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(f, TestAuth.EnsureAdmin(f), "gatekeeper", ["viewer"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/v1/applications")).StatusCode);
    }

    public static IEnumerable<object[]> BadTokens()
    {
        yield return ["alg-none"];
        yield return ["hs256-with-public-key"];
        yield return ["other-signer"];
        yield return ["wrong-issuer"];
        yield return ["wrong-audience"];
        yield return ["expired"];
        yield return ["wrong-typ"];
        yield return ["no-expiry"];
        yield return ["tampered-payload"];
        yield return ["garbage"];
    }

    [Theory]
    [MemberData(nameof(BadTokens))]
    public async Task Forged_or_invalid_tokens_are_rejected(string kind)
    {
        using var f = NewFactory();
        var good = TestAuth.AdminToken(f);
        var jwks = new JsonWebKeySet(await f.CreateClient().GetStringAsync("/.well-known/jwks.json"));
        var pub = jwks.Keys[0];
        var kid = pub.Kid;
        var h = new JsonWebTokenHandler();
        var attacker = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = kid };

        string Make(SigningCredentials creds, string iss = "gatekeeper", string aud = "gatekeeper", DateTime? exp = null, string typ = "at+jwt", bool noExp = false) =>
            h.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = iss, Audience = aud, TokenType = typ, SigningCredentials = creds,
                NotBefore = DateTime.UtcNow.AddMinutes(-10), IssuedAt = DateTime.UtcNow.AddMinutes(-10),
                Expires = noExp ? null : exp ?? DateTime.UtcNow.AddMinutes(10),
                Subject = new ClaimsIdentity([new Claim("sub", "x")]),
                Claims = new Dictionary<string, object> { ["roles"] = new[] { "admin" } },
            });

        var ec = new SigningCredentials(attacker, SecurityAlgorithms.EcdsaSha256);
        var token = kind switch
        {
            "alg-none" => Make(null!) is var _ ? NoneToken() : "",
            "hs256-with-public-key" => Make(new SigningCredentials(new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(pub.X + pub.Y + "padding-padding-padding")), SecurityAlgorithms.HmacSha256)),
            "other-signer" => Make(ec),
            "wrong-issuer" => Make(ec, iss: "evil"),
            "wrong-audience" => Make(ec, aud: "shop"),
            "expired" => Make(ec, exp: DateTime.UtcNow.AddMinutes(-5)),
            "wrong-typ" => Make(ec, typ: "JWT"),
            "no-expiry" => Make(ec, noExp: true),
            "tampered-payload" => TamperPayload(good),
            _ => "not.a.jwt",
        };

        var c = f.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/applications")).StatusCode);

        string NoneToken()
        {
            string B(string s) => Base64UrlEncoder.Encode(s);
            return $"{B("{\"alg\":\"none\",\"typ\":\"at+jwt\"}")}.{B("{\"iss\":\"gatekeeper\",\"aud\":\"gatekeeper\",\"sub\":\"x\",\"roles\":[\"admin\"],\"exp\":" + DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() + "}")}.";
        }

        static string TamperPayload(string t)
        {
            var parts = t.Split('.');
            var payload = System.Text.Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1])).Replace("\"admin\"", "\"adm1n\"");
            return $"{parts[0]}.{Base64UrlEncoder.Encode(payload)}.{parts[2]}";
        }
    }

    [Fact]
    public async Task Repeated_failures_are_throttled_with_retry_after()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var user = await Seed(admin, "shop", "buyer");
        var c = f.CreateClient();
        for (var i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await Login(c, user, "wrong password here", "shop")).StatusCode);
        var blocked = await Login(c, user, Password, "shop"); // even the right password is refused while blocked
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.NotNull(blocked.Headers.RetryAfter);
    }

    private static async Task<Guid> FindId(HttpClient c, string url, string name)
    {
        var page = await c.GetFromJsonAsync<JsonElement>(url);
        return page.GetProperty("items").EnumerateArray().Single(x => x.GetProperty("name").GetString() == name).GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Reserved_admin_app_and_role_cannot_be_renamed_or_deleted()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var app = await FindId(admin, "/v1/applications?limit=200", "gatekeeper");
        var role = await FindId(admin, $"/v1/applications/{app}/roles", "admin");
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/v1/applications/{app}")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PutAsJsonAsync($"/v1/applications/{app}", new { name = "renamed" })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/v1/roles/{role}")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PutAsJsonAsync($"/v1/roles/{role}", new { name = "boss" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync($"/v1/roles/{role}", new { name = "admin", description = "fine" })).StatusCode);
        // nobody else can claim the name
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync("/v1/applications", new { name = "gatekeeper" })).StatusCode);
        var other = await Post(admin, "/v1/applications", new { name = "other" });
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PutAsJsonAsync($"/v1/applications/{other}", new { name = "gatekeeper" })).StatusCode);
    }

    [Fact]
    public async Task A_valid_token_for_someone_who_is_not_an_administrator_is_rejected()
    {
        using var f = NewFactory();
        TestAuth.EnsureAdmin(f);
        var c = f.CreateClient();
        // Correctly signed, right audience and role claim, but the subject is not an administrator in the store.
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Token(f, "gatekeeper", ["admin"]));
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/applications")).StatusCode);
    }

    private static async Task<(Guid Id, string Name, string Token)> SecondAdmin(WebApplicationFactory<Program> f, HttpClient admin)
    {
        var app = await FindId(admin, "/v1/applications?limit=200", "gatekeeper");
        var role = await FindId(admin, $"/v1/applications/{app}/roles", "admin");
        var name = await SeedUser(admin, role);
        var user = (await (await admin.GetAsync($"/v1/users?username={name}")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("items")[0];
        var id = user.GetProperty("id").GetGuid();
        var token = TestAuth.Mint(f, new Gatekeeper.Domain.User(id, name, $"{name}@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "gatekeeper", ["admin"]);
        return (id, name, token);
    }

    [Fact]
    public async Task Demoted_or_deactivated_administrators_lose_access_immediately()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var role = await FindId(admin, $"/v1/applications/{await FindId(admin, "/v1/applications?limit=200", "gatekeeper")}/roles", "admin");

        var (id1, _, token1) = await SecondAdmin(f, admin);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/v1/users/{id1}/roles/{role}")).StatusCode); // not the last admin
        var c1 = f.CreateClient(); c1.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c1.GetAsync("/v1/applications")).StatusCode);

        var (id2, name2, token2) = await SecondAdmin(f, admin);
        var current = await (await admin.GetAsync($"/v1/users/{id2}")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync($"/v1/users/{id2}",
            new { username = name2, email = current.GetProperty("email").GetString(), displayName = "", isActive = false })).StatusCode);
        var c2 = f.CreateClient(); c2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c2.GetAsync("/v1/applications")).StatusCode);
    }

    [Fact]
    public async Task The_last_active_administrator_cannot_be_removed_deactivated_or_demoted()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var role = await FindId(admin, $"/v1/applications/{await FindId(admin, "/v1/applications?limit=200", "gatekeeper")}/roles", "admin");
        var me = TestAuth.EnsureAdmin(f).Id;

        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/v1/users/{me}")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/v1/users/{me}/roles/{role}")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PutAsJsonAsync($"/v1/users/{me}",
            new { username = TestAuth.AdminName, email = "test-admin@example.com", displayName = "", isActive = false })).StatusCode);

        // with a second administrator the first can go, and then the second is the last one
        var (id2, _, token2) = await SecondAdmin(f, admin);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/v1/users/{me}")).StatusCode);
        var c2 = f.CreateClient();
        c2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        Assert.Equal(HttpStatusCode.Conflict, (await c2.DeleteAsync($"/v1/users/{id2}")).StatusCode); // now the last one
    }

    [Fact]
    public async Task Bootstrap_repairs_an_existing_administrator()
    {
        using var f = NewFactory();
        var admin = f.CreateAdminClient();
        var me = TestAuth.EnsureAdmin(f);
        // lock the admin out: wrong password known only to the attacker-less test; then bootstrap resets it
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{me.Id}/password", new { password = "something else entirely" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(f.CreateClient(), TestAuth.AdminName, TestAuth.AdminPassword, "gatekeeper")).StatusCode);
        var created = await Bootstrap.CreateAdminAsync(f.Services, TestAuth.AdminName, "test-admin@example.com", TestAuth.AdminPassword);
        Assert.False(created);
        Assert.Equal(HttpStatusCode.OK, (await Login(f.CreateClient(), TestAuth.AdminName, TestAuth.AdminPassword, "gatekeeper")).StatusCode);
    }
}
