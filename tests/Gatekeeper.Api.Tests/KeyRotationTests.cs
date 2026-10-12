using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

public class KeyRotationTests
{
    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static WebApplicationFactory<Program> Factory(ECDsa current, string? retiredPem) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Auth:SigningKeyPem", current.ExportPkcs8PrivateKeyPem());
            if (retiredPem is not null) b.UseSetting("Auth:RetiredKeysPem", retiredPem);
        });

    private static string TokenSignedBy(ECDsa key, WebApplicationFactory<Program> f)
    {
        var admin = TestAuth.EnsureAdmin(f);
        return new TokenService(key, new AuthOptions()).Issue(
            new AuthResult(admin, new App(Guid.NewGuid(), Reserved.AdminApp), [Reserved.AdminRole])).Token;
    }

    private static async Task<HttpStatusCode> Call(WebApplicationFactory<Program> f, string token)
    {
        var c = f.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (await c.GetAsync("/v1/applications")).StatusCode;
    }

    [Fact]
    public async Task Tokens_of_a_retired_key_still_verify_and_the_jwks_lists_both_keys_current_first()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        // Only the retired key's PUBLIC half is configured, with a comment line around it.
        using var f = Factory(newKey, "# retired 2026-10-12\n" + oldKey.ExportSubjectPublicKeyInfoPem());
        var tokens = f.Services.GetRequiredService<TokenService>();

        var jwks = await f.CreateClient().GetFromJsonAsyncElement("/.well-known/jwks.json");
        var keys = jwks.GetProperty("keys").EnumerateArray().ToArray();
        Assert.Equal(2, keys.Length);
        Assert.Equal(tokens.Kid, keys[0].GetProperty("kid").GetString());
        Assert.All(keys, k => Assert.False(k.TryGetProperty("d", out _)));

        Assert.Equal(HttpStatusCode.OK, await Call(f, TokenSignedBy(oldKey, f)));  // retired: accepted
        Assert.Equal(HttpStatusCode.OK, await Call(f, TokenSignedBy(newKey, f)));  // current: accepted
        Assert.Equal(HttpStatusCode.Unauthorized, await Call(f, TokenSignedBy(NewKey(), f))); // unknown key: rejected

        // New logins are signed by the current key only.
        var login = await f.CreateClient().PostAsJsonAsyncElement("/v1/auth/login",
            new { username = TestAuth.AdminName, password = TestAuth.AdminPassword, application = "gatekeeper" });
        var jwt = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(login.GetProperty("accessToken").GetString()!);
        Assert.Equal(tokens.Kid, jwt.Kid);
    }

    [Fact]
    public async Task Removing_a_key_from_the_retired_list_revokes_the_tokens_it_signed()
    {
        var oldKey = NewKey();
        using var f = Factory(NewKey(), null);
        Assert.Equal(HttpStatusCode.Unauthorized, await Call(f, TokenSignedBy(oldKey, f)));
    }

    [Fact]
    public void Retired_keys_accept_public_or_private_blocks_and_reject_garbage()
    {
        var a = NewKey(); var b = NewKey();
        var keys = TokenService.LoadRetiredKeys(a.ExportSubjectPublicKeyInfoPem() + "\nnote\n" + b.ExportPkcs8PrivateKeyPem());
        Assert.Equal(2, keys.Count);
        Assert.Empty(TokenService.LoadRetiredKeys("# none\n"));
        Assert.Throws<ArgumentException>(() => TokenService.LoadRetiredKeys("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
        Assert.ThrowsAny<CryptographicException>(() => TokenService.LoadRetiredKeys("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"));
    }

    [Fact]
    public void The_current_key_listed_as_retired_and_duplicates_are_ignored_and_too_many_are_refused()
    {
        var cur = NewKey(); var old = NewKey();
        var t = new TokenService(cur, new AuthOptions(), [cur, old, old]);
        Assert.Equal(2, t.VerificationKeys.Count);
        Assert.Throws<ArgumentException>(() =>
            new TokenService(cur, new AuthOptions(), Enumerable.Range(0, TokenService.MaxRetiredKeys + 1).Select(_ => NewKey())));
        Assert.Throws<ArgumentException>(() => new TokenService(ECDsa.Create(ECCurve.NamedCurves.nistP384), new AuthOptions()));
    }

    [Fact]
    public void A_bad_retired_keys_setting_stops_startup()
    {
        using var f = Factory(NewKey(), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----");
        // WebApplicationFactory surfaces the startup failure when the server is first created.
        Assert.ThrowsAny<Exception>(() => f.CreateClient());
    }
}

internal static class HttpExtensions
{
    public static async Task<JsonElement> GetFromJsonAsyncElement(this HttpClient c, string url) =>
        await System.Net.Http.Json.HttpClientJsonExtensions.GetFromJsonAsync<JsonElement>(c, url);

    public static async Task<JsonElement> PostAsJsonAsyncElement(this HttpClient c, string url, object body) =>
        await (await System.Net.Http.Json.HttpClientJsonExtensions.PostAsJsonAsync(c, url, body)).Content.ReadFromJsonAsync<JsonElement>();
}
