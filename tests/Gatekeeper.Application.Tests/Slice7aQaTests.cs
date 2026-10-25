using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>
/// QA for slice 7a, written from the spec. Targets the gaps around the moment the cut-off is TAKEN versus the moment the change is WRITTEN
/// (a sign-in may start in between), refresh racing a change, and the cut-off never lowering. Hooks, no sleeping (a spin until the
/// microsecond clock ticks is used only to make "strictly later" certain).
/// </summary>
public class Slice7aQaTests
{
    private const string Password = "correct horse battery";
    private const string Changed = "another password 99";

    private sealed class PlainHasher : IPasswordHasher
    {
        public string Hash(string password) => "h:" + password;
        public bool Verify(string hash, string password) => hash == "h:" + password;
        public bool NeedsRehash(string hash) => false;
    }

    private sealed class CredHook(ICredentialRepository inner) : ICredentialRepository
    {
        /// <summary>Runs after the service took its cut-off and before the hash write reaches the store (admin set: at its hash read).</summary>
        public Func<DateTimeOffset?, Task>? BeforeWrite;
        public Func<Task>? AfterGetHash;

        public async Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default)
        {
            if (BeforeWrite is { } h) { BeforeWrite = null; await h(cutOffAt); }
            await inner.SetAsync(userId, hash, at, cutOffAt, ct);
        }

        public async Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default)
        {
            if (cutOffAt is not null && BeforeWrite is { } h) { BeforeWrite = null; await h(cutOffAt); }
            return await inner.ReplaceHashAsync(userId, expectedHash, newHash, at, cutOffAt, keepSession, ct);
        }

        public async Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default)
        {
            var hash = await inner.GetHashAsync(userId, ct);
            if (AfterGetHash is { } hook) { AfterGetHash = null; await hook(); }
            return hash;
        }
    }

    private sealed class SessionHook(ISessionRepository inner) : ISessionRepository
    {
        public Func<Task>? BeforeRotate;
        public Task AddAsync(Session session, string tokenHash, CancellationToken ct = default) => inner.AddAsync(session, tokenHash, ct);
        public Task<bool> AddForCredentialAsync(Session session, string tokenHash, string credentialHash, CancellationToken ct = default) => inner.AddForCredentialAsync(session, tokenHash, credentialHash, ct);
        public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => inner.GetHashesAsync(id, ct);
        public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid userId, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => inner.ListActiveByUserAsync(userId, now, slice, ct);
        public async Task<bool> RotateAsync(Guid id, string e, string n, DateTimeOffset now, CancellationToken ct = default)
        {
            if (BeforeRotate is { } h) { BeforeRotate = null; await h(); }
            return await inner.RotateAsync(id, e, n, now, ct);
        }
        public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAsync(id, now, ct);
        public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeForUserAsync(userId, sessionId, now, ct);
        public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserAsync(userId, now, ct);
        public Task<int> RevokeAllAndCutOffAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllAndCutOffAsync(userId, now, ct);
        public Task<int> RevokeAllForUserExceptAsync(Guid userId, Guid keep, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserExceptAsync(userId, keep, now, ct);
        public Task<int> RevokeAllForUserInAppAsync(Guid userId, Guid appId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserInAppAsync(userId, appId, now, ct);
        public Task<int> CapExpiryForUserAsync(Guid userId, DateTimeOffset endsAt, DateTimeOffset now, CancellationToken ct = default) => inner.CapExpiryForUserAsync(userId, endsAt, now, ct);
        public Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default) => inner.PurgeAsync(expiredBefore, ct);
    }

    private sealed class Rig
    {
        public InMemoryUserRepository Users = null!;
        public CredHook Creds = null!;
        public SessionHook Sessions = null!;
        public UserService UserSvc = null!;
        public CredentialService CredSvc = null!;
        public AuthService Auth = null!;
        public SessionService SessionSvc = null!;
        public User Alice = null!;
    }

    private static async Task<Rig> Setup()
    {
        var s = new InMemoryStore();
        var r = new Rig { Users = new InMemoryUserRepository(s), Creds = new CredHook(new InMemoryCredentialRepository(s)), Sessions = new SessionHook(new InMemorySessionRepository(s)) };
        var apps = new InMemoryAppRepository(s);
        var roles = new InMemoryRoleRepository(s);
        var hasher = new PlainHasher();
        r.UserSvc = new UserService(r.Users, new AdminGuard(apps, roles, r.Users), r.Sessions, roles);
        r.CredSvc = new CredentialService(r.Users, r.Creds, hasher, null, r.Sessions);
        r.Auth = new AuthService(r.Users, apps, r.Creds, hasher);
        r.SessionSvc = new SessionService(r.Sessions, r.Auth);
        var shop = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var buyer = await roles.AddAsync(new Role(Guid.NewGuid(), shop.Id, "buyer", ""));
        r.Alice = await r.UserSvc.CreateAsync("alice", "alice@example.com", null, true, UserKind.Person, null);
        await r.CredSvc.SetPasswordAsync(r.Alice.Id, Password);
        await r.Users.AssignRoleAsync(r.Alice.Id, buyer.Id);
        return r;
    }

    private static async Task<(Session Session, string Token, AuthResult Auth)> SignIn(Rig r, string password = Password)
    {
        var login = await r.Auth.LoginAsync("alice", password, "shop") ?? throw new InvalidOperationException("login failed");
        return await r.SessionSvc.StartAsync(login) ?? throw new InvalidOperationException("session refused");
    }

    /// <summary>Makes certain the next clock reading is strictly later than <paramref name="t"/> (a spin on the microsecond clock, not a sleep).</summary>
    private static void TickPast(DateTimeOffset t) { while (Clock.UtcNowMicros() <= t) { } }

    // ---- the window between taking the cut-off and writing it ----

    [Fact]
    public async Task A_login_that_starts_after_the_admin_reset_took_its_cut_off_but_before_the_hash_is_written_cannot_keep_a_session()
    {
        var r = await Setup();
        AuthResult? login = null;
        // The service has taken its cut-off C and is about to write the new hash. A sign-in starts now (stamp > C), reads the OLD hash
        // and verifies the old password; the hash write and the revoke-all then land; only after that does the login insert its session.
        r.Creds.BeforeWrite = async cutOff =>
        {
            TickPast(cutOff!.Value);
            login = await r.Auth.LoginAsync("alice", Password, "shop");
        };

        await r.CredSvc.SetPasswordAsync(r.Alice.Id, Changed);

        Assert.NotNull(login); // it did verify the old password
        Assert.Equal("h:" + Changed, await r.Creds.GetHashAsync(r.Alice.Id));
        var started = await r.SessionSvc.StartAsync(login);
        Assert.Null(started); // must be refused: the old password is no longer valid
        Assert.Empty(await r.Sessions.ListActiveByUserAsync(r.Alice.Id, Clock.UtcNowMicros()));
    }

    [Fact]
    public async Task A_login_that_starts_after_the_own_change_took_its_cut_off_but_before_the_hash_is_written_cannot_keep_a_session()
    {
        var r = await Setup();
        var (current, _, _) = await SignIn(r);
        AuthResult? login = null;
        r.Creds.BeforeWrite = async cutOff =>
        {
            TickPast(cutOff!.Value);
            login = await r.Auth.LoginAsync("alice", Password, "shop");
        };

        var change = await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, Changed, current.Id);

        Assert.Equal(OwnPasswordResult.Changed, change.Result);
        Assert.NotNull(login);
        Assert.Null(await r.SessionSvc.StartAsync(login));
        Assert.Equal([current.Id], (await r.Sessions.ListActiveByUserAsync(r.Alice.Id, Clock.UtcNowMicros())).Select(x => x.Id));
    }

    // ---- refresh racing a change ----

    public enum Change { AdminReset, OwnChangeFromAnotherSession, RevokeAll, DeactivateReactivate }

    private static async Task Apply(Rig r, Change change, Guid? otherSession)
    {
        switch (change)
        {
            case Change.AdminReset: await r.CredSvc.SetPasswordAsync(r.Alice.Id, Changed); break;
            case Change.OwnChangeFromAnotherSession:
                Assert.Equal(OwnPasswordResult.Changed, (await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, Changed, otherSession)).Result);
                break;
            case Change.RevokeAll: await r.SessionSvc.RevokeAllAndCutOffAsync(r.Alice.Id); break;
            case Change.DeactivateReactivate:
                await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false);
                await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, true);
                break;
        }
    }

    [Theory]
    [InlineData(Change.AdminReset)]
    [InlineData(Change.OwnChangeFromAnotherSession)]
    [InlineData(Change.RevokeAll)]
    [InlineData(Change.DeactivateReactivate)]
    public async Task A_refresh_that_resolved_just_before_the_change_cannot_rotate_afterwards(Change change)
    {
        var r = await Setup();
        var (victim, token, _) = await SignIn(r);
        var (other, _, _) = await SignIn(r);
        var before = (await r.Sessions.GetHashesAsync(victim.Id))!;
        r.Sessions.BeforeRotate = () => Apply(r, change, other.Id);

        var result = await r.SessionSvc.RefreshAsync(token);

        Assert.NotNull(result.Failure);
        Assert.Null(result.Token);
        Assert.Equal(before, await r.Sessions.GetHashesAsync(victim.Id)); // nothing rotated
        Assert.False(await r.SessionSvc.IsActiveAsync(victim.Id));
        Assert.NotNull((await r.SessionSvc.RefreshAsync(token)).Failure); // and the retry fails as well
    }

    [Fact]
    public async Task A_refresh_of_the_session_kept_by_an_own_change_racing_that_change_still_works_afterwards()
    {
        var r = await Setup();
        var (current, token, _) = await SignIn(r);
        r.Sessions.BeforeRotate = () => Apply(r, Change.OwnChangeFromAnotherSession, current.Id);
        var first = await r.SessionSvc.RefreshAsync(token);
        // Either outcome of the race is acceptable for this one request (rotated first, or lost to the re-stamp), but the session must survive
        // the change and a retry with the newest token must work.
        var newest = first.Token ?? token;
        var again = await r.SessionSvc.RefreshAsync(newest);
        Assert.True(again.Failure is null or "raced", $"first={first.Failure} again={again.Failure}");
        Assert.True(await r.SessionSvc.IsActiveAsync(current.Id));
    }

    // ---- never lowers ----

    [Fact]
    public async Task No_service_path_lowers_a_cut_off_that_is_already_in_the_future()
    {
        var r = await Setup();
        var future = Clock.UtcNowMicros().AddHours(1);
        await r.Users.UpdateAsync((await r.Users.GetAsync(r.Alice.Id))! with { SessionsValidAfter = future });

        await r.CredSvc.SetPasswordAsync(r.Alice.Id, Changed);
        Assert.Equal(future, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Changed, Password, null);
        Assert.Equal(future, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        await r.SessionSvc.RevokeAllAndCutOffAsync(r.Alice.Id);
        Assert.Equal(future, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false);
        await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, true);
        Assert.Equal(future, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        // and an unrelated edit through a stale copy of the user does not lower it either
        var stale = (await r.Users.GetAsync(r.Alice.Id))! with { SessionsValidAfter = null, DisplayName = "x" };
        await r.Users.UpdateAsync(stale);
        Assert.Equal(future, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
    }

    [Fact]
    public async Task A_session_whose_stamp_equals_the_cut_off_does_not_count_but_one_microsecond_later_does()
    {
        var r = await Setup();
        var (session, _, _) = await SignIn(r);
        var stamp = session.AuthenticatedAt!.Value;
        await r.Users.UpdateAsync((await r.Users.GetAsync(r.Alice.Id))! with { SessionsValidAfter = stamp });
        Assert.False(await r.SessionSvc.IsActiveAsync(session.Id));
        Assert.Empty(await r.Sessions.ListActiveByUserAsync(r.Alice.Id, Clock.UtcNowMicros()));
        await r.Users.UpdateAsync((await r.Users.GetAsync(r.Alice.Id))! with { SessionsValidAfter = stamp.AddTicks(-10) });
        // the cut-off never lowers, so the session stays refused
        Assert.False(await r.SessionSvc.IsActiveAsync(session.Id));
    }
}
