using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6a: deactivation, an earlier expiry and losing the last role in an application end or cut sessions at once.</summary>
public class Slice6aApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice6aApiTests(WebApplicationFactory<Program> factory)
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

    private record AppRole(string App, Guid AppId, Guid RoleId);

    private async Task<AppRole> NewApp(params string[] roleNames)
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var first = Guid.Empty;
        foreach (var n in roleNames)
        {
            var id = (await Post($"/v1/applications/{appId}/roles", new { name = n })).GetProperty("id").GetGuid();
            if (first == Guid.Empty) first = id;
        }
        return new AppRole(app, appId, first);
    }

    private async Task<Guid> RoleId(Guid appId, string name)
    {
        var items = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{appId}/roles")).GetProperty("items");
        return items.EnumerateArray().Single(r => r.GetProperty("name").GetString() == name).GetProperty("id").GetGuid();
    }

    private async Task<(string Name, Guid Id)> NewUser(object? extra = null)
    {
        var name = Unique("usr");
        var body = extra is null
            ? JsonSerializer.SerializeToElement(new { username = name, email = $"{name}@example.com" })
            : JsonSerializer.SerializeToElement(new { username = name, email = $"{name}@example.com", kind = "test", expiresAt = extra });
        var id = (await Post("/v1/users", body)).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private async Task Grant(Guid user, Guid role) =>
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{user}/roles/{role}", null)).StatusCode);

    private async Task<string> Login(string user, string app)
    {
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;
    }

    private Task<HttpResponseMessage> Refresh(string token) =>
        _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = token });

    private async Task<JsonElement> Sessions(Guid user) =>
        (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions")).GetProperty("items");

    [Fact]
    public async Task Deactivating_ends_all_sessions_at_once_and_reactivating_does_not_revive_them()
    {
        var a = await NewApp("member");
        var b = await NewApp("member");
        var u = await NewUser();
        var other = await NewUser();
        await Grant(u.Id, a.RoleId); await Grant(u.Id, b.RoleId); await Grant(other.Id, a.RoleId);
        var tokenA = await Login(u.Name, a.App);
        var tokenB = await Login(u.Name, b.App);
        var otherToken = await Login(other.Name, a.App);

        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false })).StatusCode);
        // revoked eagerly: nobody has tried to refresh yet, and the list is already empty
        Assert.Equal(0, (await Sessions(u.Id)).GetArrayLength());
        Assert.Equal(1, (await Sessions(other.Id)).GetArrayLength());

        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = true })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tokenA)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tokenB)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(otherToken)).StatusCode);
        // a fresh sign-in works again
        Assert.StartsWith("gkr_", await Login(u.Name, a.App));
    }

    [Fact]
    public async Task Put_with_isActive_false_also_ends_sessions_and_the_audit_row_names_the_count()
    {
        var a = await NewApp("member");
        var u = await NewUser();
        await Grant(u.Id, a.RoleId);
        await Login(u.Name, a.App); await Login(u.Name, a.App);
        var cur = await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}");
        Assert.Equal(HttpStatusCode.OK, (await _admin.PutAsJsonAsync($"/v1/users/{u.Id}",
            new { username = cur.GetProperty("username").GetString(), email = cur.GetProperty("email").GetString(), isActive = false })).StatusCode);
        Assert.Equal(0, (await Sessions(u.Id)).GetArrayLength());
        var rows = await _admin.GetStringAsync("/v1/audit?limit=20");
        Assert.Contains("sessionsRevoked=2", rows);
        Assert.DoesNotContain("sessionsRevoked=0", rows);
    }

    [Fact]
    public async Task A_change_that_does_not_deactivate_leaves_sessions_alone()
    {
        var a = await NewApp("member");
        var u = await NewUser();
        await Grant(u.Id, a.RoleId);
        var token = await Login(u.Name, a.App);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { displayName = "New" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = true })).StatusCode);
        Assert.Equal(1, (await Sessions(u.Id)).GetArrayLength());
        Assert.Equal(HttpStatusCode.OK, (await Refresh(token)).StatusCode);
    }

    [Fact]
    public async Task An_earlier_test_expiry_caps_sessions_and_a_later_extension_does_not_lengthen_them()
    {
        var a = await NewApp("member");
        var far = DateTimeOffset.UtcNow.AddDays(10);
        var u = await NewUser(far.ToString("O"));
        await Grant(u.Id, a.RoleId);
        await Login(u.Name, a.App);
        Assert.Equal(far, (await Sessions(u.Id))[0].GetProperty("expiresAt").GetDateTimeOffset(), TimeSpan.FromSeconds(1));

        var soon = DateTimeOffset.UtcNow.AddDays(2);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { expiresAt = soon })).StatusCode);
        Assert.Equal(soon, (await Sessions(u.Id))[0].GetProperty("expiresAt").GetDateTimeOffset(), TimeSpan.FromSeconds(1));

        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { expiresAt = DateTimeOffset.UtcNow.AddDays(20) })).StatusCode);
        Assert.Equal(soon, (await Sessions(u.Id))[0].GetProperty("expiresAt").GetDateTimeOffset(), TimeSpan.FromSeconds(1));
        Assert.Contains("sessionsCapped=1", await _admin.GetStringAsync("/v1/audit?limit=20"));
    }

    [Fact]
    public async Task A_person_who_becomes_a_test_user_has_their_sessions_capped()
    {
        var a = await NewApp("member");
        var u = await NewUser();
        await Grant(u.Id, a.RoleId);
        await Login(u.Name, a.App);
        var soon = DateTimeOffset.UtcNow.AddDays(3);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { kind = "test", expiresAt = soon })).StatusCode);
        Assert.Equal(soon, (await Sessions(u.Id))[0].GetProperty("expiresAt").GetDateTimeOffset(), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Losing_the_last_role_in_an_application_ends_only_that_applications_sessions()
    {
        var a = await NewApp("member", "editor");
        var b = await NewApp("member");
        var editorA = await RoleId(a.AppId, "editor");
        var u = await NewUser();
        var other = await NewUser();
        await Grant(u.Id, a.RoleId); await Grant(u.Id, editorA); await Grant(u.Id, b.RoleId); await Grant(other.Id, a.RoleId);
        var tokenA = await Login(u.Name, a.App);
        var tokenB = await Login(u.Name, b.App);
        var otherToken = await Login(other.Name, a.App);

        // one of two roles in A: the session stays
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/users/{u.Id}/roles/{editorA}")).StatusCode);
        Assert.Equal(2, (await Sessions(u.Id)).GetArrayLength());

        // the last role in A: A's session goes at once, B's and the other user's stay
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/users/{u.Id}/roles/{a.RoleId}")).StatusCode);
        var left = await Sessions(u.Id);
        Assert.Equal(1, left.GetArrayLength());
        Assert.Equal(1, (await Sessions(other.Id)).GetArrayLength());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tokenA)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(tokenB)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(otherToken)).StatusCode);

        // a role that is not held is still a 404 and revokes nothing
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/v1/users/{u.Id}/roles/{a.RoleId}")).StatusCode);
        Assert.Equal(1, (await Sessions(u.Id)).GetArrayLength());
    }

    [Fact]
    public async Task Setting_a_password_ends_all_sessions_of_that_user_only()
    {
        var a = await NewApp("member");
        var u = await NewUser();
        var other = await NewUser();
        await Grant(u.Id, a.RoleId); await Grant(other.Id, a.RoleId);
        var token = await Login(u.Name, a.App);
        await Login(u.Name, a.App);
        await Login(other.Name, a.App);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{u.Id}/password", new { password = "another long password" })).StatusCode);
        Assert.Equal(0, (await Sessions(u.Id)).GetArrayLength());
        Assert.Equal(1, (await Sessions(other.Id)).GetArrayLength());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(token)).StatusCode);
    }
}
