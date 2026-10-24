using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6b: session revoke scoped to the owner, with user and session in the audit row.</summary>
public class Slice6bApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice6bApiTests(WebApplicationFactory<Program> factory)
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

    private async Task<(string App, Guid RoleId)> NewApp()
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        return (app, (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid());
    }

    private async Task<(string Name, Guid Id, string Refresh)> UserWithSession((string App, Guid RoleId) a)
    {
        var name = Unique("usr");
        var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{id}/roles/{a.RoleId}", null)).StatusCode);
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = a.App, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (name, id, (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!);
    }

    private async Task<Guid> SessionId(Guid user) =>
        (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions")).GetProperty("items")[0].GetProperty("id").GetGuid();

    private Task<HttpResponseMessage> Refresh(string token) =>
        _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = token });

    [Fact]
    public async Task Scoped_revoke_ends_the_session_and_the_audit_row_names_user_and_session()
    {
        var a = await NewApp();
        var u = await UserWithSession(a);
        var sid = await SessionId(u.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{sid}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(u.Refresh)).StatusCode);
        Assert.Empty((await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions")).GetProperty("items").EnumerateArray());
        var rows = await _admin.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("DELETE /v1/users/{id}/sessions/{sessionId}"));
        Assert.Contains($"id={u.Id} sessionId={sid}", rows);
    }

    [Fact]
    public async Task Another_users_session_and_an_unknown_session_give_the_same_404_and_change_nothing()
    {
        var a = await NewApp();
        var owner = await UserWithSession(a);
        var other = await UserWithSession(a);
        var sid = await SessionId(owner.Id);

        var wrongUser = await _admin.DeleteAsync($"/v1/users/{other.Id}/sessions/{sid}");
        var unknown = await _admin.DeleteAsync($"/v1/users/{other.Id}/sessions/{Guid.NewGuid()}");
        var unknownUser = await _admin.DeleteAsync($"/v1/users/{Guid.NewGuid()}/sessions/{sid}");
        Assert.Equal(HttpStatusCode.NotFound, wrongUser.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknownUser.StatusCode);
        // No detail reveals which case it was: only the id from the route differs.
        var w = (await wrongUser.Content.ReadAsStringAsync()).Replace(sid.ToString(), "S");
        var n = (await unknown.Content.ReadAsStringAsync()).Replace(sid.ToString(), "S");
        Assert.Equal(JsonDocument.Parse(w).RootElement.GetProperty("title").GetString(), JsonDocument.Parse(n).RootElement.GetProperty("title").GetString());

        Assert.Equal(HttpStatusCode.OK, (await Refresh(owner.Refresh)).StatusCode);   // still alive
        Assert.Single((await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{other.Id}/sessions")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Get_single_session_is_scoped_to_the_user()
    {
        var a = await NewApp();
        var u = await UserWithSession(a);
        var other = await UserWithSession(a);
        var sid = await SessionId(u.Id);
        var ok = await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions/{sid}");
        Assert.Equal(sid, ok.GetProperty("id").GetGuid());
        Assert.Equal(u.Id, ok.GetProperty("userId").GetGuid());
        Assert.False(ok.TryGetProperty("tokenHash", out _));
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/v1/users/{other.Id}/sessions/{sid}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/v1/users/{u.Id}/sessions/{Guid.NewGuid()}")).StatusCode);
        await _admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{sid}");
        var revoked = await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions/{sid}"); // the row is kept
        Assert.NotEqual(JsonValueKind.Null, revoked.GetProperty("revokedAt").ValueKind);
    }

    [Fact]
    public async Task Old_route_still_works_and_records_the_owner_in_the_audit_note()
    {
        var a = await NewApp();
        var u = await UserWithSession(a);
        var sid = await SessionId(u.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/sessions/{sid}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(u.Refresh)).StatusCode);
        var rows = await _admin.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("DELETE /v1/sessions/{id}"));
        Assert.Contains($"user={u.Id}", rows);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/v1/sessions/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task Old_route_answers_with_deprecation_and_successor_link_headers()
    {
        var u = await UserWithSession(await NewApp());
        var sid = await SessionId(u.Id);
        var r = await _admin.DeleteAsync($"/v1/sessions/{sid}");
        Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
        Assert.Equal("true", r.Headers.GetValues("Deprecation").Single());
        Assert.Equal($"</v1/users/{u.Id}/sessions/{sid}>; rel=\"successor-version\"", r.Headers.GetValues("Link").Single());
        Assert.False(r.Headers.Contains("Sunset"));
        var scoped = await _admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{sid}");
        Assert.False(scoped.Headers.Contains("Deprecation"));
    }

    [Fact]
    public async Task Session_routes_need_an_admin_token()
    {
        var u = await UserWithSession(await NewApp());
        var sid = await SessionId(u.Id);
        var nonAdmin = _factory.CreateClient();
        nonAdmin.DefaultRequestHeaders.Authorization = new("Bearer", TestAuth.Mint(_factory, TestAuth.EnsureAdmin(_factory), "gatekeeper", ["viewer"]));
        var urls = new[] { $"/v1/users/{u.Id}/sessions/{sid}", $"/v1/sessions/{sid}" };
        foreach (var (client, expected) in new[] { (_factory.CreateClient(), HttpStatusCode.Unauthorized), (nonAdmin, HttpStatusCode.Forbidden) })
            foreach (var method in new[] { HttpMethod.Get, HttpMethod.Delete })
                foreach (var url in urls)
                {
                    if (method == HttpMethod.Get && url.StartsWith("/v1/sessions/")) continue; // no such GET route
                    Assert.Equal(expected, (await client.SendAsync(new HttpRequestMessage(method, url))).StatusCode);
                }
        Assert.Single((await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions")).GetProperty("items").EnumerateArray()); // nothing was revoked
    }

    [Fact]
    public void Every_management_endpoint_requires_the_admin_policy()
    {
        var sources = _factory.Services.GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>().Endpoints.OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>();
        // /v1/me is the self-service group (policy "self", see Slice6fApiTests); everything else must be admin.
        var open = sources.Where(e => e.RoutePattern.RawText is { } t && t.StartsWith("/v1") && !t.StartsWith("/v1/auth") && !t.StartsWith("/v1/me")
                && !e.Metadata.OfType<Microsoft.AspNetCore.Authorization.IAuthorizeData>().Any(a => a.Policy == Endpoints.AdminPolicy))
            .Select(e => e.RoutePattern.RawText).ToList();
        Assert.Empty(open);
    }

    [Fact]
    public async Task Old_route_is_marked_deprecated_in_the_served_openapi_and_the_new_routes_are_listed()
    {
        var doc = JsonDocument.Parse(await _factory.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement.GetProperty("paths");
        Assert.True(doc.GetProperty("/v1/sessions/{id}").GetProperty("delete").GetProperty("deprecated").GetBoolean());
        var scoped = doc.GetProperty("/v1/users/{id}/sessions/{sessionId}");
        Assert.True(scoped.GetProperty("delete").GetProperty("responses").TryGetProperty("204", out _));
        Assert.True(scoped.GetProperty("delete").GetProperty("responses").TryGetProperty("404", out _));
        Assert.True(scoped.GetProperty("get").GetProperty("responses").TryGetProperty("404", out _));
        Assert.False(scoped.GetProperty("delete").TryGetProperty("deprecated", out _));
    }
}
