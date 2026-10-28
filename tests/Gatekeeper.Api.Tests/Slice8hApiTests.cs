using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 8h: deleting a role or an application ends the sessions that depended on it at once.</summary>
public class Slice8hApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice8hApiTests(WebApplicationFactory<Program> factory)
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

    private async Task<(string Name, Guid Id, Guid[] Roles)> NewApp(params string[] roleNames)
    {
        var name = Unique("app");
        var id = (await Post("/v1/applications", new { name })).GetProperty("id").GetGuid();
        var roles = new List<Guid>();
        foreach (var n in roleNames) roles.Add((await Post($"/v1/applications/{id}/roles", new { name = n })).GetProperty("id").GetGuid());
        return (name, id, [.. roles]);
    }

    private async Task<(string Name, Guid Id)> NewUser(params Guid[] roles)
    {
        var name = Unique("usr");
        var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        foreach (var r in roles) Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{id}/roles/{r}", null)).StatusCode);
        return (name, id);
    }

    private async Task<string> Login(string user, string app)
    {
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;
    }

    private Task<HttpResponseMessage> Refresh(string token) => _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = token });

    private async Task<int> SessionCount(Guid user) => (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions")).GetProperty("items").GetArrayLength();

    [Fact]
    public async Task Deleting_a_role_ends_the_sessions_of_users_who_have_no_other_role_there_and_the_audit_row_counts_them()
    {
        var a = await NewApp("editor", "viewer");
        var b = await NewApp("member");
        var onlyEditor = await NewUser(a.Roles[0], b.Roles[0]);
        var both = await NewUser(a.Roles[0], a.Roles[1]);
        var viewer = await NewUser(a.Roles[1]);
        var tEditorA = await Login(onlyEditor.Name, a.Name);
        var tEditorB = await Login(onlyEditor.Name, b.Name);
        var tBoth = await Login(both.Name, a.Name);
        var tViewer = await Login(viewer.Name, a.Name);

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/roles/{a.Roles[0]}")).StatusCode);

        // ended eagerly: nobody refreshed yet and the lists already show it
        Assert.Equal(1, await SessionCount(onlyEditor.Id));    // only the session in application b is left
        Assert.Equal(1, await SessionCount(both.Id));
        Assert.Equal(1, await SessionCount(viewer.Id));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tEditorA)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(tEditorB)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(tBoth)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(tViewer)).StatusCode);
        Assert.Contains("sessionsRevoked=1", await _admin.GetStringAsync("/v1/audit?limit=20"));
    }

    [Fact]
    public async Task Deleting_a_role_nobody_depends_on_ends_nothing_and_adds_no_count()
    {
        var a = await NewApp("editor", "viewer");
        var u = await NewUser(a.Roles[1]);
        var token = await Login(u.Name, a.Name);
        var before = await _admin.GetStringAsync("/v1/audit?limit=200");
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/roles/{a.Roles[0]}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(token)).StatusCode);
        var after = await _admin.GetStringAsync("/v1/audit?limit=5");
        Assert.DoesNotContain("sessionsRevoked", after.Replace(before, ""));
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/v1/roles/{a.Roles[0]}")).StatusCode);
    }

    [Fact]
    public async Task A_wrong_if_match_on_role_delete_is_412_and_ends_nothing()
    {
        var a = await NewApp("editor");
        var u = await NewUser(a.Roles[0]);
        var token = await Login(u.Name, a.Name);
        using var bad = new HttpRequestMessage(HttpMethod.Delete, $"/v1/roles/{a.Roles[0]}");
        bad.Headers.TryAddWithoutValidation("If-Match", "\"99\"");
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await _admin.SendAsync(bad)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(token)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync($"/v1/roles/{a.Roles[0]}")).StatusCode);
    }

    [Fact]
    public async Task Deleting_an_application_ends_all_its_sessions_and_leaves_other_applications_alone()
    {
        var a = await NewApp("member");
        var b = await NewApp("member");
        var u = await NewUser(a.Roles[0], b.Roles[0]);
        var noRoleHolder = await NewUser(a.Roles[0]);
        var tA = await Login(u.Name, a.Name);
        var tB = await Login(u.Name, b.Name);
        var tOther = await Login(noRoleHolder.Name, a.Name);

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/applications/{a.Id}")).StatusCode);

        Assert.Equal(1, await SessionCount(u.Id));
        Assert.Equal(0, await SessionCount(noRoleHolder.Id));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tA)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tOther)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(tB)).StatusCode);
    }

    [Fact]
    public async Task The_cached_access_answers_of_the_ended_sessions_are_forgotten_and_others_are_kept()
    {
        var a = await NewApp("editor", "viewer");
        var gone = await NewUser(a.Roles[0]);
        var kept = await NewUser(a.Roles[0], a.Roles[1]);
        await Login(gone.Name, a.Name); await Login(kept.Name, a.Name);
        async Task<Guid> SessionOf(Guid user) =>
            (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions")).GetProperty("items")[0].GetProperty("id").GetGuid();
        var goneSid = await SessionOf(gone.Id); var keptSid = await SessionOf(kept.Id);
        var cache = _factory.Services.GetRequiredService<IMemoryCache>();
        cache.Set(("access", gone.Id, (Guid?)goneSid), "cached");
        cache.Set(("access", kept.Id, (Guid?)keptSid), "cached");

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/roles/{a.Roles[0]}")).StatusCode);

        Assert.False(cache.TryGetValue(("access", gone.Id, (Guid?)goneSid), out _));
        Assert.True(cache.TryGetValue(("access", kept.Id, (Guid?)keptSid), out _));
    }
}
