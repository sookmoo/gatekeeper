using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 7a review: a busy store after the password was verified is audited as reason=busy (bounded by the existing throttles), with no password data.</summary>
public class Slice7aBusyApiTests
{
    private const string Password = "correct horse battery";

    private sealed class BusyCredentials(ICredentialRepository inner) : ICredentialRepository
    {
        public volatile bool Fail;
        public Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default) => inner.SetAsync(userId, hash, at, cutOffAt, ct);
        public Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default) => inner.GetHashAsync(userId, ct);
        public Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default) =>
            Fail && cutOffAt is not null ? throw new BusyException() : inner.ReplaceHashAsync(userId, expectedHash, newHash, at, cutOffAt, keepSession, ct);
    }

    private sealed class BusySessions(ISessionRepository inner) : ISessionRepository
    {
        public volatile bool Fail;
        public Task AddAsync(Session s, string h, CancellationToken ct = default) => inner.AddAsync(s, h, ct);
        public Task<bool> AddForCredentialAsync(Session s, string h, string c, CancellationToken ct = default) => Fail ? throw new BusyException() : inner.AddForCredentialAsync(s, h, c, ct);
        public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => inner.GetHashesAsync(id, ct);
        public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid u, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => inner.ListActiveByUserAsync(u, now, slice, ct);
        public Task<bool> RotateAsync(Guid id, string e, string n, DateTimeOffset now, CancellationToken ct = default) => inner.RotateAsync(id, e, n, now, ct);
        public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAsync(id, now, ct);
        public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeForUserAsync(userId, sessionId, now, ct);
        public Task<int> RevokeAllForUserAsync(Guid u, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserAsync(u, now, ct);
        public Task<int> RevokeAllAndCutOffAsync(Guid u, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllAndCutOffAsync(u, now, ct);
        public Task<int> RevokeAllForUserExceptAsync(Guid u, Guid keep, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserExceptAsync(u, keep, now, ct);
        public Task<int> RevokeAllForUserInAppAsync(Guid u, Guid a, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserInAppAsync(u, a, now, ct);
        public Task<int> CapExpiryForUserAsync(Guid u, DateTimeOffset e, DateTimeOffset now, CancellationToken ct = default) => inner.CapExpiryForUserAsync(u, e, now, ct);
        public Task<int> PurgeAsync(DateTimeOffset b, CancellationToken ct = default) => inner.PurgeAsync(b, ct);
    }

    private static async Task<(string Name, Guid Id)> NewUser(HttpClient admin)
    {
        var name = "u-" + Guid.NewGuid().ToString("N")[..12];
        var id = (await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password });
        return (name, id);
    }

    private static async Task<List<string?>> Details(HttpClient admin, Guid actor) =>
        (await admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=50")).GetProperty("items").EnumerateArray().Select(x => x.GetProperty("detail").GetString()).ToList();

    [Fact]
    public async Task A_login_whose_session_insert_is_busy_is_503_and_audited_as_busy()
    {
        BusySessions? sessions = null;
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
            s.AddSingleton<ISessionRepository>(sp => sessions = new BusySessions(new InMemorySessionRepository(sp.GetRequiredService<InMemoryStore>())))));
        var admin = f.CreateAdminClient();
        var (name, id) = await NewUser(admin);
        sessions!.Fail = true;
        var r = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, r.StatusCode);
        var details = await Details(admin, id);
        Assert.Contains("reason=busy", details);
        Assert.DoesNotContain(Password, string.Join('\n', details));
    }

    [Fact]
    public async Task An_own_password_change_whose_write_is_busy_after_verification_is_503_audited_and_keeps_the_throttle_slot()
    {
        BusyCredentials? creds = null;
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
            s.AddSingleton<ICredentialRepository>(sp => creds = new BusyCredentials(new InMemoryCredentialRepository(sp.GetRequiredService<InMemoryStore>())))));
        var admin = f.CreateAdminClient();
        var (name, id) = await NewUser(admin);
        var login = await (await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true })).Content.ReadFromJsonAsync<JsonElement>();
        var me = f.CreateClient();
        me.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("accessToken").GetString());
        creds!.Fail = true;

        // the per-user limit is 5 spent guesses: five busy attempts use it up (they are audited), the sixth is a 429 without a row
        for (var i = 0; i < Endpoints.PasswordFailuresPerUser; i++)
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await me.PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = "another password 99" })).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await me.PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = "another password 99" })).StatusCode);
        var details = await Details(admin, id);
        Assert.Equal(Endpoints.PasswordFailuresPerUser, details.Count(d => d!.Contains("reason=busy")));
        Assert.DoesNotContain("another password 99", string.Join('\n', details));
    }
}
