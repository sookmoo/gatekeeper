using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Gatekeeper.Api.Tests;

public class ClientApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public ClientApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..24];

    private async Task<JsonElement> Post(string url, object body)
    {
        var r = await _admin.PostAsJsonAsync(url, body);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private async Task<(Guid App, string AppName, Guid Role, Guid Client, string ClientName, string Secret)> Setup(params string[] roleNames)
    {
        var appName = Unique("app");
        var app = (await Post("/v1/applications", new { name = appName })).GetProperty("id").GetGuid();
        Guid first = default;
        var clientName = Unique("svc");
        var created = await Post("/v1/clients", new { name = clientName, application = app });
        var client = created.GetProperty("id").GetGuid();
        foreach (var n in roleNames.Length == 0 ? ["reader"] : roleNames)
        {
            var role = (await Post($"/v1/applications/{app}/roles", new { name = n })).GetProperty("id").GetGuid();
            if (first == default) first = role;
            Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/clients/{client}/roles/{role}", null)).StatusCode);
        }
        return (app, appName, first, client, clientName, created.GetProperty("secret").GetString()!);
    }

    private Task<HttpResponseMessage> Token(string? id, string? secret) =>
        _factory.CreateClient().PostAsJsonAsync("/v1/auth/client-token", new { clientId = id, clientSecret = secret });

    [Fact]
    public async Task Secret_is_shown_once_and_the_token_carries_the_applications_roles()
    {
        var (app, appName, _, client, name, secret) = await Setup("reader", "writer");
        Assert.StartsWith("gks_", secret);
        Assert.DoesNotContain("secret", (await _admin.GetStringAsync($"/v1/clients/{client}")).ToLowerInvariant());
        Assert.DoesNotContain(secret, await _admin.GetStringAsync("/v1/clients"));

        var ok = await Token(name, secret);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("no-store", ok.Headers.CacheControl?.ToString());
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken((await ok.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!);
        Assert.Equal(appName, jwt.Audiences.Single());
        Assert.Equal(client.ToString(), jwt.Subject);
        Assert.Equal(name, jwt.GetClaim("client_id").Value);
        Assert.Equal(["reader", "writer"], jwt.Claims.Where(c => c.Type == "roles").Select(c => c.Value).Order());
        Assert.False(jwt.TryGetClaim("preferred_username", out _));
        Assert.Equal("at+jwt", jwt.Typ);
        Assert.NotEqual(Guid.Empty, app);
    }

    [Fact]
    public async Task A_client_token_cannot_manage_gatekeeper()
    {
        var (_, _, _, _, name, secret) = await Setup();
        var token = (await (await Token(name, secret)).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/applications")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/health/ready")).StatusCode);
    }

    [Fact]
    public async Task Every_failure_is_the_same_401()
    {
        var (_, _, _, client, name, secret) = await Setup();
        var inactive = await Post("/v1/clients", new { name = Unique("off"), application = (await Setup()).App, isActive = false });
        var inactiveName = inactive.GetProperty("name").GetString();
        var inactiveSecret = inactive.GetProperty("secret").GetString();
        var noRoles = await Post("/v1/clients", new { name = Unique("bare"), application = (await Setup()).App });

        var bodies = new List<string>();
        foreach (var (id, s) in new (string?, string?)[]
                 {
                     (name, secret + "x"), ("no-such-client", secret), (inactiveName, inactiveSecret), (noRoles.GetProperty("name").GetString(), noRoles.GetProperty("secret").GetString()),
                     (null, null), ("Bad Name!", "short"), (name, ""), (name, new string('z', 5000)),
                 })
        {
            var r = await Token(id, s);
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            bodies.Add(await r.Content.ReadAsStringAsync());
        }
        Assert.Single(bodies.Select(b => JsonDocument.Parse(b).RootElement.GetProperty("detail").GetString()).Distinct());
        Assert.Equal(HttpStatusCode.OK, (await Token(name.ToUpperInvariant(), secret)).StatusCode); // names are case-insensitive
        Assert.NotEqual(Guid.Empty, client);
    }

    [Fact]
    public async Task Rotating_replaces_the_secret_and_disabling_stops_the_client()
    {
        var (_, _, _, client, name, secret) = await Setup();
        var rotated = (await Post($"/v1/clients/{client}/secret", new { })).GetProperty("secret").GetString()!;
        Assert.NotEqual(secret, rotated);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Token(name, secret)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Token(name, rotated)).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/clients/{client}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Token(name, rotated)).StatusCode);
        await _admin.PatchAsJsonAsync($"/v1/clients/{client}", new { isActive = true });
        Assert.Equal(HttpStatusCode.OK, (await Token(name, rotated)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/clients/{client}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Token(name, rotated)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync($"/v1/clients/{client}/secret", new { })).StatusCode);
    }

    [Fact]
    public async Task Rules_the_admin_app_a_foreign_role_and_names()
    {
        var (app, _, _, client, _, _) = await Setup();
        var gatekeeper = (await _admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray()
            .First(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PostAsJsonAsync("/v1/clients", new { name = Unique("bad"), application = gatekeeper })).StatusCode);

        var otherApp = (await Post("/v1/applications", new { name = Unique("other") })).GetProperty("id").GetGuid();
        var foreign = (await Post($"/v1/applications/{otherApp}/roles", new { name = "x" })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PutAsync($"/v1/clients/{client}/roles/{foreign}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsync($"/v1/clients/{client}/roles/{Guid.NewGuid()}", null)).StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PostAsJsonAsync("/v1/clients", new { name = "Bad Name", application = app })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync("/v1/clients", new { name = Unique("ok"), application = Guid.NewGuid() })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync("/v1/clients", new { name = Unique("ok") })).StatusCode); // no application
        var name = Unique("dup");
        Assert.Equal(HttpStatusCode.Created, (await _admin.PostAsJsonAsync("/v1/clients", new { name, application = app })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PostAsJsonAsync("/v1/clients", new { name, application = app })).StatusCode);

        // Without a role the client cannot get a token, and deleting the app removes the client.
        var bare = await Post("/v1/clients", new { name = Unique("bare"), application = otherApp });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Token(bare.GetProperty("name").GetString(), bare.GetProperty("secret").GetString())).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/applications/{app}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/v1/clients/{client}")).StatusCode);
    }

    [Fact]
    public async Task Management_needs_admin_and_secrets_stay_out_of_the_audit_trail()
    {
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/v1/clients")).StatusCode);
        var (_, _, _, client, name, secret) = await Setup();
        var rotated = (await Post($"/v1/clients/{client}/secret", new { })).GetProperty("secret").GetString()!;
        await Token(name, "wrong secret value here");
        var audit = await _admin.GetStringAsync("/v1/audit?limit=200");
        Assert.DoesNotContain(secret, audit);
        Assert.DoesNotContain(rotated, audit);
        Assert.Contains("auth.client-token", audit);
        Assert.Contains("/v1/clients/{id:guid}/secret", audit);
        Assert.Equal("no-store", (await _admin.PostAsJsonAsync("/v1/clients", new { name = Unique("ns"), application = (await Setup()).App })).Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Repeated_failures_are_throttled()
    {
        using var f = _factory.WithWebHostBuilder(_ => { });
        var c = f.CreateClient();
        HttpStatusCode last = default;
        for (var i = 0; i < 12; i++)
            last = (await c.PostAsJsonAsync("/v1/auth/client-token", new { clientId = "throttled-one", clientSecret = "wrong secret value" })).StatusCode;
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
    }
}
