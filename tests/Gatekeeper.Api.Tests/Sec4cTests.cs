using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Security review of slice 4c. Each test states the finding it demonstrates.</summary>
public class Sec4cTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Sec4cTests(WebApplicationFactory<Program> factory)
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

    private record Person(string Username, Guid UserId, string App, Guid AppId);

    private async Task<Person> NewPerson(HttpClient? admin = null)
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var roleId = (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        var name = Unique("usr");
        var userId = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        await _admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password = Password });
        await _admin.PutAsync($"/v1/users/{userId}/roles/{roleId}", null);
        return new Person(name, userId, app, appId);
    }


    // Regression: a PRIVATE KEY block in the retired list never leaks private parameters into the JWKS.
    [Fact]
    public async Task Retired_private_key_block_does_not_leak_into_the_jwks()
    {
        var old = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Auth:SigningKeyPem", ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportPkcs8PrivateKeyPem());
            b.UseSetting("Auth:RetiredKeysPem", old.ExportPkcs8PrivateKeyPem());
        });
        var text = await f.CreateClient().GetStringAsync("/.well-known/jwks.json");
        var d = Convert.ToBase64String(old.ExportParameters(true).D!).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.DoesNotContain(d, text);
        Assert.DoesNotContain("\"d\"", text);
    }




    // Regression: a client of application A cannot learn anything about application B's tokens or users.
    [Fact]
    public async Task Introspect_other_applications_token_is_inactive()
    {
        var a = await NewPerson();
        var b = await NewPerson();
        var verifier = await Post("/v1/clients", new { name = Unique("ver"), application = b.AppId });
        var tok = (await (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login",
            new { username = a.Username, password = Password, application = a.App })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{verifier.GetProperty("name").GetString()}:{verifier.GetProperty("secret").GetString()}")));
        var body = await (await c.PostAsJsonAsync("/v1/auth/introspect", new { token = tok })).Content.ReadAsStringAsync();
        Assert.Equal("{\"active\":false}", body);
    }
}
