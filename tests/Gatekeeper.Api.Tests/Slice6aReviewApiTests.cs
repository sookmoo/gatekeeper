using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6a review: a request cancelled after the user row was saved is audited as cancelled, and repeating it repairs the sessions.</summary>
public class Slice6aReviewApiTests
{
    private const string Password = "correct horse battery";

    private sealed class CancelOnce(ISessionRepository inner) : ISessionRepository
    {
        public volatile bool Armed;
        public Task AddAsync(Session s, string h, CancellationToken ct = default) => inner.AddAsync(s, h, ct);
        public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => inner.GetHashesAsync(id, ct);
        public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid u, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => inner.ListActiveByUserAsync(u, now, slice, ct);
        public Task<bool> RotateAsync(Guid id, string e, string n, DateTimeOffset now, CancellationToken ct = default) => inner.RotateAsync(id, e, n, now, ct);
        public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAsync(id, now, ct);
        public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeForUserAsync(userId, sessionId, now, ct);
        public Task<int> RevokeAllForUserExceptAsync(Guid u, Guid keep, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserExceptAsync(u, keep, now, ct);
        public Task<int> RevokeAllForUserAsync(Guid u, DateTimeOffset now, CancellationToken ct = default)
        {
            if (Armed) { Armed = false; throw new OperationCanceledException("simulated disconnect"); }
            return inner.RevokeAllForUserAsync(u, now, ct);
        }
        public Task<int> RevokeAllForUserInAppAsync(Guid u, Guid a, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserInAppAsync(u, a, now, ct);
        public Task<int> CapExpiryForUserAsync(Guid u, DateTimeOffset e, DateTimeOffset now, CancellationToken ct = default) => inner.CapExpiryForUserAsync(u, e, now, ct);
        public Task<int> PurgeAsync(DateTimeOffset b, CancellationToken ct = default) => inner.PurgeAsync(b, ct);
    }

    private sealed class AfterAddHook(ISessionRepository inner) : ISessionRepository
    {
        public Func<Task>? Hook;
        public async Task AddAsync(Session s, string h, CancellationToken ct = default) { await inner.AddAsync(s, h, ct); if (Hook is { } k) { Hook = null; await k(); } }
        public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => inner.GetHashesAsync(id, ct);
        public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid u, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => inner.ListActiveByUserAsync(u, now, slice, ct);
        public Task<bool> RotateAsync(Guid id, string e, string n, DateTimeOffset now, CancellationToken ct = default) => inner.RotateAsync(id, e, n, now, ct);
        public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAsync(id, now, ct);
        public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeForUserAsync(userId, sessionId, now, ct);
        public Task<int> RevokeAllForUserExceptAsync(Guid u, Guid keep, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserExceptAsync(u, keep, now, ct);
        public Task<int> RevokeAllForUserAsync(Guid u, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserAsync(u, now, ct);
        public Task<int> RevokeAllForUserInAppAsync(Guid u, Guid a, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserInAppAsync(u, a, now, ct);
        public Task<int> CapExpiryForUserAsync(Guid u, DateTimeOffset e, DateTimeOffset now, CancellationToken ct = default) => inner.CapExpiryForUserAsync(u, e, now, ct);
        public Task<int> PurgeAsync(DateTimeOffset b, CancellationToken ct = default) => inner.PurgeAsync(b, ct);
    }

    [Fact]
    public async Task A_login_that_races_a_deactivation_is_401_and_only_a_raced_failure_is_audited()
    {
        AfterAddHook? hook = null;
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
            s.AddSingleton<ISessionRepository>(sp => hook = new AfterAddHook(new InMemorySessionRepository(sp.GetRequiredService<InMemoryStore>())))));
        var admin = f.CreateAdminClient();
        async Task<JsonElement> Post(string url, object body)
        {
            var r = await admin.PostAsJsonAsync(url, body);
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }
        var app = "app-" + Guid.NewGuid().ToString("N")[..10];
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var role = (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        var name = "u-" + Guid.NewGuid().ToString("N")[..10];
        var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password });
        await admin.PutAsync($"/v1/users/{id}/roles/{role}", null);

        var users = f.Services.GetRequiredService<IUserRepository>();
        hook!.Hook = async () => await users.UpdateAsync((await users.GetAsync(id))! with { IsActive = false });
        var login = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        var rows = (await admin.GetFromJsonAsync<JsonElement>($"/v1/audit?action=auth.login&actor={id}")).GetProperty("items");
        Assert.Equal(1, rows.GetArrayLength());
        Assert.Equal("failure", rows[0].GetProperty("outcome").GetString());
        Assert.Contains("raced", rows[0].GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Cancelled_deactivation_is_audited_and_the_same_request_again_ends_the_sessions()
    {
        CancelOnce? hook = null;
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            s.AddSingleton<ISessionRepository>(sp => hook = new CancelOnce(new InMemorySessionRepository(sp.GetRequiredService<InMemoryStore>())));
        }));
        var admin = f.CreateAdminClient();
        async Task<JsonElement> Post(string url, object body)
        {
            var r = await admin.PostAsJsonAsync(url, body);
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }
        var app = "app-" + Guid.NewGuid().ToString("N")[..10];
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var role = (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        var name = "u-" + Guid.NewGuid().ToString("N")[..10];
        var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password });
        await admin.PutAsync($"/v1/users/{id}/roles/{role}", null);
        var login = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        hook!.Armed = true;
        try { await admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false }); } catch (OperationCanceledException) { }
        // saved, but the revoke step did not finish
        Assert.False((await admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}")).GetProperty("isActive").GetBoolean());
        Assert.Equal(1, (await admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        var audit = await admin.GetStringAsync("/v1/audit?limit=20");
        Assert.Contains("cancelled", audit);

        Assert.Equal(HttpStatusCode.OK, (await admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false })).StatusCode);
        Assert.Equal(0, (await admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        Assert.Contains("sessionsRevoked=1", await admin.GetStringAsync("/v1/audit?limit=20"));
    }
}
