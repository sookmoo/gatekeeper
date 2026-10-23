using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>Slice 6a review round: retries repair half-done changes, stale sessions never come back, login cannot race a deactivation.</summary>
public class Slice6aReviewTests
{
    private sealed class PlainHasher : IPasswordHasher
    {
        public string Hash(string password) => "h:" + password;
        public bool Verify(string hash, string password) => hash == "h:" + password;
        public bool NeedsRehash(string hash) => false;
    }

    /// <summary>Session store that can throw once on chosen calls and run a hook after a session was added (no sleeping, fully deterministic).</summary>
    private sealed class Hooked(ISessionRepository inner) : ISessionRepository
    {
        public bool FailNextRevokeAll, FailNextRevokeInApp, FailNextCap;
        public Func<Task>? AfterAdd;
        private static void Boom(ref bool flag) { if (flag) { flag = false; throw new StoreUnavailableException("simulated failure"); } }

        public async Task AddAsync(Session session, string tokenHash, CancellationToken ct = default)
        {
            await inner.AddAsync(session, tokenHash, ct);
            if (AfterAdd is { } h) { AfterAdd = null; await h(); }
        }
        public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => inner.GetHashesAsync(id, ct);
        public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid userId, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => inner.ListActiveByUserAsync(userId, now, slice, ct);
        public Task<bool> RotateAsync(Guid id, string e, string n, DateTimeOffset now, CancellationToken ct = default) => inner.RotateAsync(id, e, n, now, ct);
        public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAsync(id, now, ct);
        public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeForUserAsync(userId, sessionId, now, ct);
        public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) { Boom(ref FailNextRevokeAll); return inner.RevokeAllForUserAsync(userId, now, ct); }
        public Task<int> RevokeAllForUserInAppAsync(Guid userId, Guid appId, DateTimeOffset now, CancellationToken ct = default) { Boom(ref FailNextRevokeInApp); return inner.RevokeAllForUserInAppAsync(userId, appId, now, ct); }
        public Task<int> CapExpiryForUserAsync(Guid userId, DateTimeOffset endsAt, DateTimeOffset now, CancellationToken ct = default) { Boom(ref FailNextCap); return inner.CapExpiryForUserAsync(userId, endsAt, now, ct); }
        public Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default) => inner.PurgeAsync(expiredBefore, ct);
    }

    private sealed class Rig
    {
        public InMemoryUserRepository Users = null!;
        public InMemoryAppRepository Apps = null!;
        public InMemoryRoleRepository Roles = null!;
        public InMemoryCredentialRepository Creds = null!;
        public Hooked Sessions = null!;
        public UserService Svc = null!;
        public SessionService SessionSvc = null!;
        public AuthService Auth = null!;
        public App Shop = null!, Blog = null!;
        public Role Buyer = null!, Extra = null!, Writer = null!;
    }

    private static async Task<Rig> Setup()
    {
        var s = new InMemoryStore();
        var r = new Rig { Apps = new InMemoryAppRepository(s), Roles = new InMemoryRoleRepository(s), Users = new InMemoryUserRepository(s), Creds = new InMemoryCredentialRepository(s) };
        r.Sessions = new Hooked(new InMemorySessionRepository(s));
        var guard = new AdminGuard(r.Apps, r.Roles, r.Users);
        r.Svc = new UserService(r.Users, guard, r.Sessions, r.Roles);
        r.Auth = new AuthService(r.Users, r.Apps, r.Creds, new PlainHasher());
        r.SessionSvc = new SessionService(r.Sessions, r.Auth);
        r.Shop = await r.Apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        r.Blog = await r.Apps.AddAsync(new App(Guid.NewGuid(), "blog"));
        r.Buyer = await r.Roles.AddAsync(new Role(Guid.NewGuid(), r.Shop.Id, "buyer", ""));
        r.Extra = await r.Roles.AddAsync(new Role(Guid.NewGuid(), r.Shop.Id, "extra", ""));
        r.Writer = await r.Roles.AddAsync(new Role(Guid.NewGuid(), r.Blog.Id, "writer", ""));
        return r;
    }

    private static Session NewSession(Guid user, Guid app, TimeSpan? life = null)
    {
        var now = Clock.UtcNowMicros();
        return new Session(Guid.NewGuid(), user, app, now, now, now + (life ?? TimeSpan.FromDays(10)), null);
    }

    private static async Task<Session> Add(Rig r, Guid user, Guid app, TimeSpan? life = null)
    {
        var x = NewSession(user, app, life);
        await r.Sessions.AddAsync(x, "h" + x.Id);
        return x;
    }

    private static async Task<bool> Alive(Rig r, Session x) => (await r.Sessions.GetAsync(x.Id))!.IsActive(Clock.UtcNowMicros());

    [Fact]
    public async Task A_failed_revoke_after_deactivation_is_repaired_by_repeating_the_request()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("alice", "alice@example.com", null);
        var x = await Add(r, u.Id, r.Shop.Id);
        r.Sessions.FailNextRevokeAll = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.Svc.PatchAsync(u.Id, null, null, null, false));
        Assert.False((await r.Svc.GetAsync(u.Id)).IsActive); // saved...
        Assert.True(await Alive(r, x));                      // ...but the session step failed
        // The same request again: the user is already inactive, so a change-edge rule would do nothing. The saved state decides.
        var (_, fx) = await r.Svc.PatchWithEffectsAsync(u.Id, null, null, null, false);
        Assert.Equal(1, fx.Revoked);
        Assert.False(await Alive(r, x));
    }

    [Fact]
    public async Task A_failed_cap_is_repaired_by_saving_the_test_user_again()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("tester", "t@example.com", null, true, UserKind.Test, Clock.UtcNowMicros().AddDays(10));
        var x = await Add(r, u.Id, r.Shop.Id, TimeSpan.FromDays(10));
        var soon = Clock.UtcNowMicros().AddDays(2);
        r.Sessions.FailNextCap = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.Svc.PatchAsync(u.Id, null, null, null, null, null, soon));
        Assert.True((await r.Sessions.GetAsync(x.Id))!.ExpiresAt > soon.AddDays(1));
        var (_, fx) = await r.Svc.PatchWithEffectsAsync(u.Id, null, null, null, null, null, null); // nothing new asked: saved state still caps
        Assert.Equal(1, fx.Capped);
        Assert.Equal((await r.Svc.GetAsync(u.Id)).ExpiresAt, (await r.Sessions.GetAsync(x.Id))!.ExpiresAt);
    }

    [Fact]
    public async Task A_cancelled_request_still_finishes_the_session_steps_after_the_save()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("alice", "alice@example.com", null);
        var x = await Add(r, u.Id, r.Shop.Id);
        using var cts = new CancellationTokenSource();
        // cancel once the user row is saved: the session steps must not observe the token
        var cancelling = new CancelOnUpdate(r.Users, cts);
        var svc = new UserService(cancelling, null, r.Sessions, r.Roles);
        await svc.UpdateAsync(u.Id, u.Username, u.Email, u.DisplayName, false, null, null, ct: cts.Token);
        Assert.True(cts.IsCancellationRequested);
        Assert.False(await Alive(r, x));
    }

    private sealed class CancelOnUpdate(IUserRepository inner, CancellationTokenSource cts) : IUserRepository
    {
        public async Task<User?> UpdateAsync(User user, long? expectedVersion = null, CancellationToken ct = default) { var u = await inner.UpdateAsync(user, expectedVersion, ct); cts.Cancel(); return u; }
        public Task<User> AddAsync(User user, CancellationToken ct = default) => inner.AddAsync(user, ct);
        public Task<User?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, UserKind? kind = null, Slice? slice = null, CancellationToken ct = default) => inner.ListAsync(active, username, kind, slice, ct);
        public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default) => inner.DeleteAsync(id, expectedVersion, ct);
        public Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default) => inner.AssignRoleAsync(userId, roleId, ct);
        public Task<bool> RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default) => inner.RevokeRoleAsync(userId, roleId, ct);
        public Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null, Slice? slice = null, CancellationToken ct = default) => inner.ListRolesAsync(userId, appId, slice, ct);
        public Task<int> CountActiveWithRoleAsync(Guid roleId, Guid? excludingUserId, CancellationToken ct = default) => inner.CountActiveWithRoleAsync(roleId, excludingUserId, ct);
    }

    [Fact]
    public async Task Reactivation_revokes_every_session_even_stale_ones_from_before()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("alice", "alice@example.com", null, isActive: false);
        // a leftover from before the change shipped: the user is inactive but a session is still marked active
        var stale = await Add(r, u.Id, r.Shop.Id);
        var other = await r.Svc.CreateAsync("bob", "bob@example.com", null);
        var bobs = await Add(r, other.Id, r.Shop.Id);
        var (_, fx) = await r.Svc.PatchWithEffectsAsync(u.Id, null, null, null, true);
        Assert.Equal(1, fx.Revoked);
        Assert.False(await Alive(r, stale));
        Assert.True(await Alive(r, bobs));
    }

    [Fact]
    public async Task Assigning_a_first_role_in_an_application_revokes_stale_sessions_there_only()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("alice", "alice@example.com", null);
        var staleShop = await Add(r, u.Id, r.Shop.Id);
        var staleBlog = await Add(r, u.Id, r.Blog.Id);
        await r.Svc.AssignRoleAsync(u.Id, r.Buyer.Id);
        Assert.False(await Alive(r, staleShop));
        Assert.True(await Alive(r, staleBlog)); // the other application is not touched
        // a second role in the same application: the user already has access there, so live sessions stay
        var live = await Add(r, u.Id, r.Shop.Id);
        await r.Svc.AssignRoleAsync(u.Id, r.Extra.Id);
        Assert.True(await Alive(r, live));
        // an unknown role is a store error and revokes nothing
        await Assert.ThrowsAsync<NotFoundException>(() => r.Svc.AssignRoleAsync(u.Id, Guid.NewGuid()));
        Assert.True(await Alive(r, live));
    }

    [Fact]
    public async Task Role_removal_uses_the_roles_own_application_and_a_retry_repairs_a_failed_step()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("alice", "alice@example.com", null);
        await r.Svc.AssignRoleAsync(u.Id, r.Buyer.Id);
        await r.Svc.AssignRoleAsync(u.Id, r.Extra.Id);
        await r.Svc.AssignRoleAsync(u.Id, r.Writer.Id);
        var shop = await Add(r, u.Id, r.Shop.Id);
        var blog = await Add(r, u.Id, r.Blog.Id);

        await r.Svc.RevokeRoleAsync(u.Id, r.Buyer.Id); // another shop role remains
        Assert.True(await Alive(r, shop));

        r.Sessions.FailNextRevokeInApp = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.Svc.RevokeRoleAsync(u.Id, r.Extra.Id)); // last shop role: removed, session step failed
        Assert.True(await Alive(r, shop));
        // the retry finds the assignment gone (404) but still finishes the job
        await Assert.ThrowsAsync<NotFoundException>(() => r.Svc.RevokeRoleAsync(u.Id, r.Extra.Id));
        Assert.False(await Alive(r, shop));
        Assert.True(await Alive(r, blog));
    }

    [Fact]
    public async Task Removing_an_unknown_role_or_one_in_an_application_where_roles_remain_revokes_nothing()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("alice", "alice@example.com", null);
        await r.Svc.AssignRoleAsync(u.Id, r.Buyer.Id);
        var shop = await Add(r, u.Id, r.Shop.Id);
        await Assert.ThrowsAsync<NotFoundException>(() => r.Svc.RevokeRoleAsync(u.Id, Guid.NewGuid()));
        await Assert.ThrowsAsync<NotFoundException>(() => r.Svc.RevokeRoleAsync(u.Id, r.Extra.Id)); // not held, but a role is still held in shop
        Assert.True(await Alive(r, shop));
    }

    private async Task<(Rig R, User U, AuthResult Login)> LoggedIn(string name = "alice", DateTimeOffset? expires = null)
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync(name, $"{name}@example.com", null, true, expires is null ? UserKind.Person : UserKind.Test, expires);
        await r.Svc.AssignRoleAsync(u.Id, r.Buyer.Id);
        var login = await r.Auth.ResolveAsync(u.Id, r.Shop.Id) ?? throw new InvalidOperationException();
        return (r, u, login);
    }

    [Fact]
    public async Task A_login_that_races_a_deactivation_gets_no_session()
    {
        var (r, u, login) = await LoggedIn();
        // the deactivation lands between the credential check and the insert: its revoke-all sees no session yet
        // (applied at the store level: going through the service would also revoke the new row and hide the race)
        r.Sessions.AfterAdd = async () => await r.Users.UpdateAsync((await r.Users.GetAsync(u.Id))! with { IsActive = false });
        Assert.Null(await r.SessionSvc.StartAsync(login));
        Assert.Empty(await r.Sessions.ListActiveByUserAsync(u.Id, Clock.UtcNowMicros()));
    }

    [Fact]
    public async Task A_login_that_races_the_removal_of_the_last_role_gets_no_session()
    {
        var (r, u, login) = await LoggedIn();
        r.Sessions.AfterAdd = async () => await r.Users.RevokeRoleAsync(u.Id, r.Buyer.Id);
        Assert.Null(await r.SessionSvc.StartAsync(login));
        Assert.Empty(await r.Sessions.ListActiveByUserAsync(u.Id, Clock.UtcNowMicros()));
    }

    [Fact]
    public async Task A_login_that_races_an_earlier_expiry_gets_a_capped_session()
    {
        var (r, u, login) = await LoggedIn("tester", Clock.UtcNowMicros().AddDays(20));
        var soon = Clock.UtcNowMicros().AddDays(1);
        r.Sessions.AfterAdd = async () => await r.Users.UpdateAsync((await r.Users.GetAsync(u.Id))! with { ExpiresAt = soon });
        var started = await r.SessionSvc.StartAsync(login);
        Assert.NotNull(started);
        Assert.Equal(soon, started!.Value.Session.ExpiresAt);
        Assert.Equal(soon, (await r.Sessions.GetAsync(started.Value.Session.Id))!.ExpiresAt);
    }

    [Fact]
    public async Task A_normal_login_still_starts_a_session()
    {
        var (r, u, login) = await LoggedIn();
        var started = await r.SessionSvc.StartAsync(login);
        Assert.NotNull(started);
        Assert.Single(await r.Sessions.ListActiveByUserAsync(u.Id, Clock.UtcNowMicros()));
    }

    [Fact]
    public async Task Extending_an_expired_test_user_revokes_the_sessions_left_from_before()
    {
        var r = await Setup();
        var u = await r.Svc.CreateAsync("tester", "t@example.com", null, true, UserKind.Test, Clock.UtcNowMicros().AddDays(2));
        var stale = await Add(r, u.Id, r.Shop.Id);
        // the account expires (set directly, as time passing would), the session row is still marked active
        await r.Users.UpdateAsync((await r.Users.GetAsync(u.Id))! with { ExpiresAt = Clock.UtcNowMicros().AddSeconds(-1) });
        Assert.True(await Alive(r, stale));
        var (_, fx) = await r.Svc.PatchWithEffectsAsync(u.Id, null, null, null, null, null, Clock.UtcNowMicros().AddDays(5));
        Assert.Equal(1, fx.Revoked);
        Assert.False(await Alive(r, stale));
    }

    [Fact]
    public async Task Editing_a_usable_test_user_does_not_revoke_sessions()
    {
        var (r, u, login) = await LoggedIn("tester", Clock.UtcNowMicros().AddDays(5));
        var started = await r.SessionSvc.StartAsync(login);
        var (_, fx) = await r.Svc.PatchWithEffectsAsync(u.Id, null, null, "New name", null);
        Assert.Equal(0, fx.Revoked);
        Assert.True(await Alive(r, (await r.Sessions.GetAsync(started!.Value.Session.Id))!));
    }

    [Fact]
    public async Task Start_returns_the_roles_read_after_the_insert()
    {
        var (r, u, login) = await LoggedIn();
        r.Sessions.AfterAdd = async () => await r.Svc.AssignRoleAsync(u.Id, r.Extra.Id);
        var started = await r.SessionSvc.StartAsync(login);
        Assert.Equal(["buyer", "extra"], started!.Value.Auth.Roles.Order());
    }
}
