using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

public class QaSpecTests(WebApplicationFactory<Program> f) : IClassFixture<WebApplicationFactory<Program>>
{
    private HttpClient C => f.CreateClient();
    private static string N(string p) => $"{p}-{Guid.NewGuid():N}"[..20];
    private static StringContent J(string s) => new(s, Encoding.UTF8, "application/json");

    private static async Task<JsonElement> Body(HttpResponseMessage r) =>
        JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement.Clone();

    private async Task<Guid> MkApp(HttpClient c, string? name = null)
    {
        var r = await c.PostAsJsonAsync("/v1/applications", new { name = name ?? N("app") });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await Body(r)).GetProperty("id").GetGuid();
    }
    private async Task<Guid> MkRole(HttpClient c, Guid app, string? name = null)
    {
        var r = await c.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = name ?? N("role") });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await Body(r)).GetProperty("id").GetGuid();
    }
    private async Task<Guid> MkUser(HttpClient c, string? u = null, string? e = null)
    {
        u ??= N("user");
        var r = await c.PostAsJsonAsync("/v1/users", new { username = u, email = e ?? $"{u}@example.com" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await Body(r)).GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Create_returns_201_with_location_and_problem_json_on_errors()
    {
        var c = C;
        var r = await c.PostAsJsonAsync("/v1/applications", new { name = N("app") });
        var id = (await Body(r)).GetProperty("id").GetGuid();
        Assert.EndsWith($"/v1/applications/{id}", r.Headers.Location!.ToString());
        var bad = await c.PostAsJsonAsync("/v1/applications", new { name = "Bad Name" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal("application/problem+json", bad.Content.Headers.ContentType!.MediaType);
        var nf = await c.GetAsync($"/v1/applications/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, nf.StatusCode);
        Assert.Equal("application/problem+json", nf.Content.Headers.ContentType!.MediaType);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{\"name\":5}")]
    public async Task Malformed_body_is_400_not_500(string body)
    {
        var r = await C.PostAsync("/v1/applications", J(body));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Empty_body_is_400()
    {
        var r = await C.PostAsync("/v1/users", new StringContent("", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Missing_content_type_is_not_500()
    {
        var r = await C.PostAsync("/v1/users", new StringContent("{}"));
        Assert.True((int)r.StatusCode < 500, r.StatusCode.ToString());
    }

    [Fact]
    public async Task App_name_unique_case_insensitive_on_create_and_update()
    {
        var c = C; var n = N("app");
        await MkApp(c, n);
        // uppercase is rejected by slug rule OR conflicts; either is acceptable but must not be 201
        var r = await c.PostAsJsonAsync("/v1/applications", new { name = n.ToUpperInvariant() });
        Assert.NotEqual(HttpStatusCode.Created, r.StatusCode);
        var other = await MkApp(c);
        var put = await c.PutAsJsonAsync($"/v1/applications/{other}", new { name = n });
        Assert.Equal(HttpStatusCode.Conflict, put.StatusCode);
        // rename to itself ok
        var self = await c.PutAsJsonAsync($"/v1/applications/{other}", new { name = (await Body(await c.GetAsync($"/v1/applications/{other}"))).GetProperty("name").GetString() });
        Assert.Equal(HttpStatusCode.OK, self.StatusCode);
    }

    [Fact]
    public async Task User_email_unique_case_insensitive_and_username_conflict()
    {
        var c = C; var u = N("user");
        await MkUser(c, u, $"{u}@Example.com");
        var r = await c.PostAsJsonAsync("/v1/users", new { username = N("u2"), email = $"{u}@EXAMPLE.COM" });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        var r2 = await c.PostAsJsonAsync("/v1/users", new { username = u, email = $"x{u}@example.com" });
        Assert.Equal(HttpStatusCode.Conflict, r2.StatusCode);
        // update to other's email -> 409
        var other = await MkUser(c);
        var put = await c.PutAsJsonAsync($"/v1/users/{other}", new { username = N("u3"), email = $"{u}@example.com", isActive = true });
        Assert.Equal(HttpStatusCode.Conflict, put.StatusCode);
    }

    [Fact]
    public async Task Username_with_uppercase_is_rejected_usernames_are_lowercase_slugs()
    {
        // Decision: usernames are lowercase slugs (uniqueness stays case-insensitive as defence in depth).
        var r = await C.PostAsJsonAsync("/v1/users", new { username = "Alice" + Guid.NewGuid().ToString("N")[..6], email = $"{Guid.NewGuid():N}@example.com" });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Theory]
    [InlineData("a@b")]
    [InlineData("a b@c.d")]
    [InlineData("@c.d")]
    [InlineData("")]
    public async Task Bad_email_is_400(string email)
    {
        var r = await C.PostAsJsonAsync("/v1/users", new { username = N("user"), email });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Role_name_unique_per_app_only()
    {
        var c = C; var a1 = await MkApp(c); var a2 = await MkApp(c);
        await MkRole(c, a1, "admin");
        await MkRole(c, a2, "admin");
        var dup = await c.PostAsJsonAsync($"/v1/applications/{a1}/roles", new { name = "admin" });
        Assert.Equal(HttpStatusCode.Conflict, dup.StatusCode);
        var viewer = await MkRole(c, a1, "viewer");
        var put = await c.PutAsJsonAsync($"/v1/roles/{viewer}", new { name = "admin" });
        Assert.Equal(HttpStatusCode.Conflict, put.StatusCode);
        var nf = await c.PostAsJsonAsync($"/v1/applications/{Guid.NewGuid()}/roles", new { name = "x" });
        Assert.Equal(HttpStatusCode.NotFound, nf.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/v1/applications/{Guid.NewGuid()}/roles")).StatusCode);
    }

    [Fact]
    public async Task Cascade_app_delete_removes_roles_and_assignments()
    {
        var c = C; var app = await MkApp(c); var role = await MkRole(c, app); var user = await MkUser(c);
        Assert.Equal(HttpStatusCode.NoContent, (await c.PutAsync($"/v1/users/{user}/roles/{role}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/v1/applications/{app}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/v1/roles/{role}")).StatusCode);
        var roles = await Body(await c.GetAsync($"/v1/users/{user}/roles"));
        Assert.Equal(0, roles.GetArrayLength());
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/v1/applications/{app}/roles")).StatusCode);
    }

    [Fact]
    public async Task Cascade_role_delete_and_user_delete()
    {
        var c = C; var app = await MkApp(c); var r1 = await MkRole(c, app); var r2 = await MkRole(c, app);
        var u = await MkUser(c);
        await c.PutAsync($"/v1/users/{u}/roles/{r1}", null); await c.PutAsync($"/v1/users/{u}/roles/{r2}", null);
        await c.DeleteAsync($"/v1/roles/{r1}");
        Assert.Equal(1, (await Body(await c.GetAsync($"/v1/users/{u}/roles"))).GetArrayLength());
        await c.DeleteAsync($"/v1/users/{u}");
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/v1/users/{u}/roles")).StatusCode);
        // role survives user deletion; re-created user with same name has no roles
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync($"/v1/roles/{r2}")).StatusCode);
    }

    [Fact]
    public async Task Assign_idempotent_revoke_semantics_and_404s()
    {
        var c = C; var app = await MkApp(c); var role = await MkRole(c, app); var u = await MkUser(c);
        Assert.Equal(HttpStatusCode.NoContent, (await c.PutAsync($"/v1/users/{u}/roles/{role}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.PutAsync($"/v1/users/{u}/roles/{role}", null)).StatusCode);
        Assert.Equal(1, (await Body(await c.GetAsync($"/v1/users/{u}/roles"))).GetArrayLength());
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsync($"/v1/users/{u}/roles/{Guid.NewGuid()}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsync($"/v1/users/{Guid.NewGuid()}/roles/{role}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/v1/users/{u}/roles/{role}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync($"/v1/users/{u}/roles/{role}")).StatusCode);
    }

    [Fact]
    public async Task Roles_filter_by_application_and_users_filter_by_active()
    {
        var c = C; var a1 = await MkApp(c); var a2 = await MkApp(c);
        var r1 = await MkRole(c, a1); var r2 = await MkRole(c, a2); var u = await MkUser(c);
        await c.PutAsync($"/v1/users/{u}/roles/{r1}", null); await c.PutAsync($"/v1/users/{u}/roles/{r2}", null);
        var f = await Body(await c.GetAsync($"/v1/users/{u}/roles?application={a1}"));
        Assert.Equal(1, f.GetArrayLength()); Assert.Equal(r1, f[0].GetProperty("id").GetGuid());
        Assert.Equal(0, (await Body(await c.GetAsync($"/v1/users/{u}/roles?application={Guid.NewGuid()}"))).GetArrayLength());

        var inactive = N("user");
        await c.PostAsJsonAsync("/v1/users", new { username = inactive, email = $"{inactive}@example.com", isActive = false });
        var act = await Body(await c.GetAsync("/v1/users?active=false"));
        Assert.Contains(act.EnumerateArray(), x => x.GetProperty("username").GetString() == inactive);
        Assert.All(act.EnumerateArray(), x => Assert.False(x.GetProperty("isActive").GetBoolean()));
        var tr = await Body(await c.GetAsync("/v1/users?active=true"));
        Assert.DoesNotContain(tr.EnumerateArray(), x => x.GetProperty("username").GetString() == inactive);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/v1/users?active=maybe")).StatusCode);
    }

    [Fact]
    public async Task User_update_bumps_updatedAt_keeps_createdAt_and_defaults_active()
    {
        var c = C; var u = N("user");
        var created = await Body(await c.PostAsJsonAsync("/v1/users", new { username = u, email = $"{u}@example.com" }));
        Assert.True(created.GetProperty("isActive").GetBoolean());
        await Task.Delay(20);
        var put = await Body(await c.PutAsJsonAsync($"/v1/users/{created.GetProperty("id").GetGuid()}", new { username = u, email = $"{u}@example.com", displayName = "X", isActive = false }));
        Assert.Equal(created.GetProperty("createdAt").GetDateTimeOffset(), put.GetProperty("createdAt").GetDateTimeOffset());
        Assert.True(put.GetProperty("updatedAt").GetDateTimeOffset() > created.GetProperty("updatedAt").GetDateTimeOffset());
    }

    [Fact]
    public async Task Put_and_delete_unknown_ids_404_and_non_guid_not_500()
    {
        var c = C; var g = Guid.NewGuid();
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsJsonAsync($"/v1/applications/{g}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsJsonAsync($"/v1/roles/{g}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsJsonAsync($"/v1/users/{g}", new { username = "x", email = "a@b.co" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync($"/v1/users/{g}")).StatusCode);
        Assert.True((int)(await c.GetAsync("/v1/users/not-a-guid")).StatusCode is 400 or 404);
    }

    [Fact]
    public async Task Health_and_openapi()
    {
        var c = C;
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/openapi/v1.json")).StatusCode);
    }

    // ---- concurrency on the in-memory store ----

    [Fact]
    public async Task Concurrent_duplicate_creates_yield_exactly_one_success()
    {
        var c = C; var n = N("app");
        var rs = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => c.PostAsJsonAsync("/v1/applications", new { name = n })));
        Assert.Equal(1, rs.Count(r => r.StatusCode == HttpStatusCode.Created));
        Assert.Equal(49, rs.Count(r => r.StatusCode == HttpStatusCode.Conflict));
    }

    [Fact]
    public async Task Race_create_role_vs_delete_app_leaves_no_orphan_roles()
    {
        // RoleService.CreateAsync checks the app then adds the role without holding the store lock.
        var store = f.Services.GetRequiredService<InMemoryStore>();
        var apps = f.Services.GetRequiredService<AppService>();
        var roles = f.Services.GetRequiredService<RoleService>();
        for (int i = 0; i < 300; i++)
        {
            var a = await apps.CreateAsync(N("app"));
            var create = Task.Run(async () => { try { await roles.CreateAsync(a.Id, "r", ""); } catch (NotFoundException) { } });
            var del = Task.Run(() => apps.DeleteAsync(a.Id));
            await Task.WhenAll(create, del);
        }
        lock (store.Gate)
            Assert.DoesNotContain(store.Roles.Values, r => !store.Apps.ContainsKey(r.AppId));
    }

    [Fact]
    public async Task Race_assign_vs_role_delete_leaves_no_dangling_assignment()
    {
        var store = f.Services.GetRequiredService<InMemoryStore>();
        var apps = f.Services.GetRequiredService<AppService>();
        var roles = f.Services.GetRequiredService<RoleService>();
        var users = f.Services.GetRequiredService<UserService>();
        var a = await apps.CreateAsync(N("app"));
        for (int i = 0; i < 300; i++)
        {
            var role = await roles.CreateAsync(a.Id, $"r{i}", "");
            var u = await users.CreateAsync(N("user"), $"{Guid.NewGuid():N}@example.com", null);
            var t1 = Task.Run(async () => { try { await users.AssignRoleAsync(u.Id, role.Id); } catch (NotFoundException) { } });
            var t2 = Task.Run(() => roles.DeleteAsync(role.Id));
            await Task.WhenAll(t1, t2);
        }
        lock (store.Gate)
            Assert.DoesNotContain(store.Assignments, x => !store.Roles.ContainsKey(x.RoleId) || !store.Users.ContainsKey(x.UserId));
    }
}
