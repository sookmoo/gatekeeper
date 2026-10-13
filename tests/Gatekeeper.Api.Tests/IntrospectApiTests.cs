using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

public class IntrospectApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public IntrospectApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<JsonElement> Post(string url, object body)
    {
        var r = await _admin.PostAsJsonAsync(url, body);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    /// <summary>An application with a role, a user holding it, and a verifier client with no roles.</summary>
    private record World(string App, Guid AppId, Guid RoleId, string User, Guid UserId, string Verifier, string VerifierSecret);

    private async Task<World> NewWorld(params string[] roles)
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        Guid firstRole = default;
        var user = Unique("usr");
        var userId = (await Post("/v1/users", new { username = user, email = $"{user}@example.com" })).GetProperty("id").GetGuid();
        await _admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password = Password });
        foreach (var n in roles.Length == 0 ? ["reader"] : roles)
        {
            var role = (await Post($"/v1/applications/{appId}/roles", new { name = n })).GetProperty("id").GetGuid();
            if (firstRole == default) firstRole = role;
            await _admin.PutAsync($"/v1/users/{userId}/roles/{role}", null);
        }
        var verifier = await Post("/v1/clients", new { name = Unique("ver"), application = appId });
        return new World(app, appId, firstRole, user, userId, verifier.GetProperty("name").GetString()!, verifier.GetProperty("secret").GetString()!);
    }

    private async Task<JsonElement> UserLogin(World w, bool refresh = false) =>
        await (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login",
            new { username = w.User, password = Password, application = w.App, refresh })).Content.ReadFromJsonAsync<JsonElement>();

    private async Task<HttpResponseMessage> Introspect(string? token, string? id, string? secret, string scheme = "Basic")
    {
        var c = _factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token }) };
        if (id is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue(scheme, Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));
        return await c.SendAsync(req);
    }

    private async Task<JsonElement> Ask(World w, string? token) =>
        await (await Introspect(token, w.Verifier, w.VerifierSecret)).Content.ReadFromJsonAsync<JsonElement>();

    [Fact]
    public async Task An_active_user_token_is_described_with_the_current_roles()
    {
        var w = await NewWorld("reader", "writer");
        var login = await UserLogin(w, refresh: true);
        var answer = await Ask(w, login.GetProperty("accessToken").GetString());
        Assert.True(answer.GetProperty("active").GetBoolean());
        Assert.Equal(w.UserId.ToString(), answer.GetProperty("sub").GetString());
        Assert.Equal(w.User, answer.GetProperty("preferred_username").GetString());
        Assert.Equal(w.App, answer.GetProperty("aud").GetString());
        Assert.Equal(["reader", "writer"], answer.GetProperty("roles").EnumerateArray().Select(r => r.GetString()));
        Assert.True(answer.TryGetProperty("sid", out _));
        Assert.False(answer.TryGetProperty("client_id", out _));
        Assert.InRange(answer.GetProperty("exp").GetInt64(), DateTimeOffset.UtcNow.ToUnixTimeSeconds(), DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());
    }

    [Fact]
    public async Task Changes_in_the_world_show_up_at_once()
    {
        var w = await NewWorld("reader", "writer");
        var token = (await UserLogin(w)).GetProperty("accessToken").GetString();

        var writer = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{w.UserId}/roles")).GetProperty("items").EnumerateArray()
            .First(r => r.GetProperty("name").GetString() == "writer").GetProperty("id").GetGuid();
        await _admin.DeleteAsync($"/v1/users/{w.UserId}/roles/{writer}");
        Assert.Equal(["reader"], (await Ask(w, token)).GetProperty("roles").EnumerateArray().Select(r => r.GetString())); // the token still says writer

        await _admin.PatchAsJsonAsync($"/v1/users/{w.UserId}", new { isActive = false });
        Assert.False((await Ask(w, token)).GetProperty("active").GetBoolean());
        await _admin.PatchAsJsonAsync($"/v1/users/{w.UserId}", new { isActive = true });
        Assert.True((await Ask(w, token)).GetProperty("active").GetBoolean());

        await _admin.DeleteAsync($"/v1/users/{w.UserId}/roles/{w.RoleId}"); // no roles left
        Assert.False((await Ask(w, token)).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Ending_the_session_deactivates_its_access_tokens()
    {
        var w = await NewWorld();
        var login = await UserLogin(w, refresh: true);
        var access = login.GetProperty("accessToken").GetString();
        Assert.True((await Ask(w, access)).GetProperty("active").GetBoolean());
        await _factory.CreateClient().PostAsJsonAsync("/v1/auth/logout", new { refreshToken = login.GetProperty("refreshToken").GetString() });
        Assert.False((await Ask(w, access)).GetProperty("active").GetBoolean());
        // A token from a login without a session cannot be ended that way, but is not affected either.
        Assert.True((await Ask(w, (await UserLogin(w)).GetProperty("accessToken").GetString())).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Anything_that_is_not_a_good_token_for_the_callers_application_is_just_inactive()
    {
        var w = await NewWorld();
        var other = await NewWorld();
        var tokens = _factory.Services.GetRequiredService<TokenService>();
        var users = _factory.Services.GetRequiredService<IUserRepository>();
        var user = (await users.GetAsync(w.UserId))!;
        var app = new Gatekeeper.Domain.App(w.AppId, w.App);
        var good = (await UserLogin(w)).GetProperty("accessToken").GetString()!;
        var expired = tokens.Issue(new AuthResult(user, app, ["reader"]), DateTimeOffset.UtcNow.AddHours(-1)).Token;
        var wrongKey = new TokenService(System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256), new AuthOptions())
            .Issue(new AuthResult(user, app, ["reader"])).Token;
        var adminToken = TestAuth.AdminToken(_factory);
        var otherToken = (await UserLogin(other)).GetProperty("accessToken").GetString();

        foreach (var bad in new string?[] { null, "", "x", "a.b.c", good + "x", good[..^3] + "AAA", expired, wrongKey, adminToken, otherToken, new string('a', 20000) })
        {
            var r = await Introspect(bad, w.Verifier, w.VerifierSecret);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var body = await r.Content.ReadAsStringAsync();
            Assert.Equal("""{"active":false}""", body);
        }
        Assert.True((await Ask(w, good)).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Client_tokens_can_be_introspected_and_disabling_the_client_deactivates_them()
    {
        var w = await NewWorld();
        var created = await Post("/v1/clients", new { name = Unique("svc"), application = w.AppId });
        var clientId = created.GetProperty("id").GetGuid();
        await _admin.PutAsync($"/v1/clients/{clientId}/roles/{w.RoleId}", null);
        var token = (await (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/client-token",
            new { clientId = created.GetProperty("name").GetString(), clientSecret = created.GetProperty("secret").GetString() })).Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("accessToken").GetString();

        var answer = await Ask(w, token);
        Assert.True(answer.GetProperty("active").GetBoolean());
        Assert.Equal(created.GetProperty("name").GetString(), answer.GetProperty("client_id").GetString());
        Assert.False(answer.TryGetProperty("preferred_username", out _));

        await _admin.PatchAsJsonAsync($"/v1/clients/{clientId}", new { isActive = false });
        Assert.False((await Ask(w, token)).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task The_caller_must_be_a_valid_client_and_every_failure_looks_the_same()
    {
        var w = await NewWorld();
        var token = (await UserLogin(w)).GetProperty("accessToken").GetString();
        var disabled = await Post("/v1/clients", new { name = Unique("off"), application = w.AppId, isActive = false });
        var bodies = new HashSet<string>();
        foreach (var (id, secret, scheme) in new (string?, string?, string)[]
                 {
                     (null, null, "Basic"), (w.Verifier, "wrong secret value", "Basic"), ("no-such-client", w.VerifierSecret, "Basic"),
                     (disabled.GetProperty("name").GetString(), disabled.GetProperty("secret").GetString(), "Basic"),
                     (w.Verifier, w.VerifierSecret, "Bearer"), ("Bad Name!", "x", "Basic"),
                 })
        {
            var r = await Introspect(token, id, secret, scheme);
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.StartsWith("Basic", r.Headers.WwwAuthenticate.ToString());
            bodies.Add(await r.Content.ReadAsStringAsync());
        }
        Assert.Single(bodies.Select(b => JsonDocument.Parse(b).RootElement.GetProperty("detail").GetString()).Distinct());
        // A user or an admin token is not a way in.
        Assert.Equal(HttpStatusCode.Unauthorized, (await Introspect(token, w.User, Password)).StatusCode);
        // Garbage in the header never throws.
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Basic !!!not-base64!!!");
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsJsonAsync("/v1/auth/introspect", new { token })).StatusCode);
    }

    [Fact]
    public async Task A_verifier_client_without_roles_works_but_cannot_get_tokens()
    {
        var w = await NewWorld();
        var tokenAttempt = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/client-token", new { clientId = w.Verifier, clientSecret = w.VerifierSecret });
        Assert.Equal(HttpStatusCode.Unauthorized, tokenAttempt.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Introspect("x", w.Verifier, w.VerifierSecret)).StatusCode);
    }

    [Fact]
    public async Task Wrong_credentials_are_throttled_and_audited_without_the_secret()
    {
        using var f = _factory.WithWebHostBuilder(_ => { });
        var c = f.CreateClient();
        HttpStatusCode last = default;
        for (var i = 0; i < 12; i++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token = "x" }) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("throttled-one:gks_wrong-secret-value")));
            last = (await c.SendAsync(req)).StatusCode;
        }
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
        var audit = await _admin.GetStringAsync("/v1/audit?action=auth.introspect&limit=50");
        Assert.DoesNotContain("gks_wrong-secret-value", audit);
    }
}
