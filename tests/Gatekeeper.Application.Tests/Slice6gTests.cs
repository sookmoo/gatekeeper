using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>Slice 6g: CredentialService.ChangeOwnPasswordAsync with a controllable hasher.</summary>
public class Slice6gTests
{
    private sealed class FakeHasher : IPasswordHasher
    {
        public Action<string>? OnHash;
        public int Hashes;
        public int Verifies;
        public string Hash(string password) { Hashes++; OnHash?.Invoke(password); return "h:" + password; }
        public bool Verify(string hash, string password) { Verifies++; return hash == "h:" + password; }
        public bool NeedsRehash(string hash) => false;
    }

    private static async Task<(CredentialService Svc, ICredentialRepository Creds, FakeHasher H, User User)> Setup(UserKind kind = UserKind.Person, bool active = true)
    {
        var s = new InMemoryStore();
        var users = new InMemoryUserRepository(s);
        var creds = new InMemoryCredentialRepository(s);
        var sessions = new InMemorySessionRepository(s);
        var user = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "", active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, kind,
            kind == UserKind.Test ? DateTimeOffset.UtcNow.AddDays(1) : null));
        var h = new FakeHasher();
        await creds.SetAsync(user.Id, "h:current password 1", DateTimeOffset.UtcNow);
        return (new CredentialService(users, creds, h, null, sessions), creds, h, user);
    }

    [Fact]
    public async Task A_correct_current_password_replaces_the_hash()
    {
        var (svc, creds, _, user) = await Setup();
        var r = await svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "next password 22", null);
        Assert.Equal(OwnPasswordResult.Changed, r.Result);
        Assert.Equal("h:next password 22", await creds.GetHashAsync(user.Id));
    }

    [Theory]
    [InlineData("nope nope nope nope")]
    [InlineData("short")]
    [InlineData("")]
    public async Task Every_wrong_current_password_does_one_verification_and_changes_nothing(string current)
    {
        var (svc, creds, h, user) = await Setup();
        var r = await svc.ChangeOwnPasswordAsync(user.Id, current, "next password 22", null);
        Assert.Equal(OwnPasswordResult.WrongCurrent, r.Result);
        Assert.Equal(1, h.Verifies);
        Assert.Equal("h:current password 1", await creds.GetHashAsync(user.Id));
    }

    [Fact]
    public async Task A_user_who_cannot_use_self_service_gets_the_same_verdict_with_the_same_hash_work()
    {
        foreach (var (kind, active) in new[] { (UserKind.Shared, true), (UserKind.Person, false) })
        {
            var (svc, creds, h, user) = await Setup(kind, active);
            var r = await svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "next password 22", null);
            Assert.Equal(OwnPasswordResult.WrongCurrent, r.Result);
            Assert.Equal(1, h.Verifies);
            Assert.Equal("h:current password 1", await creds.GetHashAsync(user.Id));
        }
        var unknown = await Setup();
        Assert.Equal(OwnPasswordResult.WrongCurrent, (await unknown.Svc.ChangeOwnPasswordAsync(Guid.NewGuid(), "current password 1", "next password 22", null)).Result);
    }

    [Fact]
    public async Task The_same_password_is_unchanged_only_after_it_verified()
    {
        var (svc, creds, _, user) = await Setup();
        Assert.Equal(OwnPasswordResult.Unchanged, (await svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "current password 1", null)).Result);
        Assert.Equal(OwnPasswordResult.WrongCurrent, (await svc.ChangeOwnPasswordAsync(user.Id, "other other other", "other other other", null)).Result);
        Assert.Equal("h:current password 1", await creds.GetHashAsync(user.Id));
    }

    [Fact]
    public async Task A_password_set_meanwhile_is_not_overwritten()
    {
        var (svc, creds, h, user) = await Setup();
        // Between the verification and the write an administrator sets another password.
        h.OnHash = password => { if (password == "next password 22") creds.SetAsync(user.Id, "h:set by an admin 33", DateTimeOffset.UtcNow).GetAwaiter().GetResult(); };
        var r = await svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "next password 22", null);
        Assert.Equal(OwnPasswordResult.WrongCurrent, r.Result);
        Assert.Equal("h:set by an admin 33", await creds.GetHashAsync(user.Id));
    }

    [Fact]
    public async Task Rule_violations_are_reported_without_the_values_and_before_any_hashing()
    {
        var (svc, _, h, user) = await Setup();
        var ex = await Assert.ThrowsAsync<ValidationException>(() => svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "SECRETshort", null));
        Assert.Contains("newPassword", ex.Errors.Keys);
        Assert.DoesNotContain("SECRETshort", ex.Message + string.Join(' ', ex.Errors.Values));
        var missing = await Assert.ThrowsAsync<ValidationException>(() => svc.ChangeOwnPasswordAsync(user.Id, null, "next password 22", null));
        Assert.Contains("currentPassword", missing.Errors.Keys);
        Assert.Equal(0, h.Verifies);
    }

    // ---- review round ----

    private sealed class SuffixHasher : IPasswordHasher
    {
        public Action<string>? OnHash;
        public string Hash(string password) { OnHash?.Invoke(password); return "h:" + password; }
        public bool Verify(string hash, string password) => hash.EndsWith(":" + password); // any version prefix verifies
        public bool NeedsRehash(string hash) => false;
    }

    private static async Task<(CredentialService Svc, ICredentialRepository Creds, InMemorySessionRepository Sessions, SuffixHasher H, User User, Guid[] SessionIds)> WithSessions()
    {
        var s = new InMemoryStore();
        var users = new InMemoryUserRepository(s);
        var apps = new InMemoryAppRepository(s);
        var creds = new InMemoryCredentialRepository(s);
        var sessions = new InMemorySessionRepository(s);
        var user = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var ids = new List<Guid>();
        for (var i = 0; i < 3; i++)
        {
            var session = new Session(Guid.NewGuid(), user.Id, app.Id, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), null);
            await sessions.AddAsync(session, "hash" + i);
            ids.Add(session.Id);
        }
        var h = new SuffixHasher();
        await creds.SetAsync(user.Id, "h:current password 1", DateTimeOffset.UtcNow);
        return (new CredentialService(users, creds, h, null, sessions), creds, sessions, h, user, ids.ToArray());
    }

    [Fact]
    public async Task A_request_cancelled_after_the_hash_is_computed_still_stores_the_password_and_ends_the_other_sessions()
    {
        var (svc, creds, sessions, h, user, ids) = await WithSessions();
        using var cts = new CancellationTokenSource();
        h.OnHash = password => { if (password == "next password 22") cts.Cancel(); }; // the caller goes away right after hashing
        var r = await svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "next password 22", ids[0], cts.Token);
        Assert.Equal(OwnPasswordResult.Changed, r.Result);
        Assert.Equal(2, r.SessionsRevoked);
        Assert.Equal("h:next password 22", await creds.GetHashAsync(user.Id));
        var active = await sessions.ListActiveByUserAsync(user.Id, DateTimeOffset.UtcNow);
        Assert.Equal([ids[0]], active.Select(x => x.Id));
    }

    [Fact]
    public async Task A_hash_upgraded_by_a_concurrent_login_does_not_make_the_correct_password_look_wrong()
    {
        var (svc, creds, _, h, user, ids) = await WithSessions();
        h.OnHash = password => { if (password == "next password 22") creds.SetAsync(user.Id, "v2:current password 1", DateTimeOffset.UtcNow).GetAwaiter().GetResult(); };
        var r = await svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "next password 22", ids[0]);
        Assert.Equal(OwnPasswordResult.Changed, r.Result);
        Assert.Equal("h:next password 22", await creds.GetHashAsync(user.Id));
    }

    [Fact]
    public async Task A_deleted_user_gets_the_uniform_verdict()
    {
        var (svc, _, _, _, _, _) = await WithSessions();
        Assert.Equal(OwnPasswordResult.WrongCurrent, (await svc.ChangeOwnPasswordAsync(Guid.NewGuid(), "current password 1", "next password 22", null)).Result);
    }

    [Fact]
    public async Task Without_a_session_store_the_change_is_refused_before_anything_is_written()
    {
        var s = new InMemoryStore();
        var users = new InMemoryUserRepository(s);
        var creds = new InMemoryCredentialRepository(s);
        var user = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        await creds.SetAsync(user.Id, "h:current password 1", DateTimeOffset.UtcNow);
        var svc = new CredentialService(users, creds, new SuffixHasher());
        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.ChangeOwnPasswordAsync(user.Id, "current password 1", "next password 22", null));
        Assert.Equal("h:current password 1", await creds.GetHashAsync(user.Id));
    }
}
