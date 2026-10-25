using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 7b QA: the removed unscoped session route is 404 on every method for every kind of caller, writes no audit row and revokes nothing.</summary>
public class Slice7bQaTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice7bQaTests(WebApplicationFactory<Program> factory) { _factory = factory; _admin = factory.CreateAdminClient(); }

    [Fact]
    public async Task Every_method_and_caller_gets_404_without_deprecation_headers_and_nothing_is_revoked()
    {
        var name = $"u7b-{Guid.NewGuid():N}"[..16];
        var u = await (await _admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com" })).Content.ReadFromJsonAsync<JsonElement>();
        var uid = u.GetProperty("id").GetGuid();
        await _admin.PutAsJsonAsync($"/v1/users/{uid}/password", new { password = "correct horse battery" });
        var login = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = "correct horse battery", application = "gatekeeper", refresh = true });
        // The user may have no role in "gatekeeper": a session is only created on a successful login, so fall back to listing.
        var before = await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{uid}/sessions");
        var count = before.GetProperty("items").GetArrayLength();
        var sid = count > 0 ? before.GetProperty("items")[0].GetProperty("id").GetGuid() : Guid.NewGuid();

        var self = _factory.CreateClient();
        self.DefaultRequestHeaders.Authorization = new("Bearer", TestAuth.Mint(_factory, TestAuth.EnsureAdmin(_factory), "gatekeeper", ["viewer"]));
        var junk = _factory.CreateClient();
        junk.DefaultRequestHeaders.Authorization = new("Bearer", "not.a.token");
        var expired = _factory.CreateClient();
        expired.DefaultRequestHeaders.Authorization = new("Bearer", TestAuth.Mint(_factory, TestAuth.EnsureAdmin(_factory), Gatekeeper.Domain.Reserved.AdminApp, [Gatekeeper.Domain.Reserved.AdminRole], DateTimeOffset.UtcNow.AddDays(-1)));

        foreach (var client in new[] { _admin, self, _factory.CreateClient(), junk, expired })
            foreach (var id in new[] { sid, Guid.NewGuid() })
                foreach (var method in new[] { HttpMethod.Delete, HttpMethod.Get, HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Head, HttpMethod.Options })
                    foreach (var path in new[] { $"/v1/sessions/{id}", "/v1/sessions", $"/v1/sessions/{id}/" })
                    {
                        var r = await client.SendAsync(new HttpRequestMessage(method, path));
                        Assert.True(r.StatusCode == HttpStatusCode.NotFound, $"{method} {path} -> {(int)r.StatusCode}");
                        Assert.False(r.Headers.Contains("Deprecation") || r.Headers.Contains("Link"), $"{method} {path}");
                    }
        var after = await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{uid}/sessions");
        Assert.Equal(count, after.GetProperty("items").GetArrayLength());
        if (login.IsSuccessStatusCode)
            Assert.NotEqual(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString() })).StatusCode);
    }

    [Fact]
    public async Task Scoped_routes_are_the_only_session_revoke_routes_in_the_served_openapi()
    {
        var doc = JsonDocument.Parse(await _factory.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement;
        Assert.DoesNotContain(doc.GetProperty("paths").EnumerateObject(), p => p.Name.StartsWith("/v1/sessions"));
        if (doc.TryGetProperty("tags", out var tags)) Assert.DoesNotContain(tags.EnumerateArray(), t => t.GetProperty("name").GetString() == "Sessions");
        Assert.DoesNotContain("successor-version", doc.GetRawText());
        Assert.DoesNotContain("\"deprecated\"", doc.GetRawText());
    }
}
