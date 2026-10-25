using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>
/// Slice 7a: the per-user session cut-off. Races and half-done changes are made deterministic with hooks between the steps (no sleeping).
/// </summary>
public class Slice7aTests
{
    private const string Password = "correct horse battery";

    private sealed class PlainHasher : IPasswordHasher
    {
        public string Hash(string password) => "h:" + password;
        public bool Verify(string hash, string password) => hash == "h:" + password;
        public bool NeedsRehash(string hash) => false;
    }

    /// <summary>Runs a hook right after the stored hash was read (the login has the old hash in hand but has not verified or stored a session yet).</summary>
    private sealed class CredentialHook(ICredentialRepository inner) : ICredentialRepository
    {
        public Func<Task>? AfterGetHash;
        /// <summary>Runs after the service read its clock for the cut-off and before the store write.</summary>
        public Func<DateTimeOffset, Task>? BeforeWrite;
        public Exception? FailReplace;
        public DateTimeOffset? ClockAtGetHash;
        public async Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default)
        {
            if (cutOffAt is { } c && BeforeWrite is { } h) { BeforeWrite = null; await h(c); }
            await inner.SetAsync(userId, hash, at, cutOffAt, ct);
        }
        public async Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default)
        {
            if (FailReplace is { } boom) { FailReplace = null; throw boom; }
            if (cutOffAt is { } c && BeforeWrite is { } h) { BeforeWrite = null; await h(c); }
            return await inner.ReplaceHashAsync(userId, expectedHash, newHash, at, cutOffAt, keepSession, ct);
        }
        public async Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default)
        {
            var hash = await inner.GetHashAsync(userId, ct);
            ClockAtGetHash ??= Clock.UtcNowMicros();
            if (AfterGetHash is { } hook) { AfterGetHash = null; await hook(); }
            return hash;
        }
    }

    /// <summary>Session store whose row-level revokes can be made to fail (the cut-off must not depend on them).</summary>
    private sealed class FlakySessions(ISessionRepository inner) : ISessionRepository
    {
        public bool FailRevokeAll, FailRevokeAllExcept;
        private static void Boom(ref bool flag) { if (flag) { flag = false; throw new StoreUnavailableException("simulated failure"); } }
        public Task AddAsync(Session session, string tokenHash, CancellationToken ct = default) => inner.AddAsync(session, tokenHash, ct);
        public Task<bool> AddForCredentialAsync(Session session, string tokenHash, string credentialHash, CancellationToken ct = default) => inner.AddForCredentialAsync(session, tokenHash, credentialHash, ct);
        public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => inner.GetAsync(id, ct);
        public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => inner.GetHashesAsync(id, ct);
        public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid userId, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => inner.ListActiveByUserAsync(userId, now, slice, ct);
        public Task<bool> RotateAsync(Guid id, string e, string n, DateTimeOffset now, CancellationToken ct = default) => inner.RotateAsync(id, e, n, now, ct);
        public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAsync(id, now, ct);
        public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeForUserAsync(userId, sessionId, now, ct);
        public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) { Boom(ref FailRevokeAll); return inner.RevokeAllForUserAsync(userId, now, ct); }
        public Task<int> RevokeAllAndCutOffAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllAndCutOffAsync(userId, now, ct);
        public Task<int> RevokeAllForUserExceptAsync(Guid userId, Guid keep, DateTimeOffset now, CancellationToken ct = default) { Boom(ref FailRevokeAllExcept); return inner.RevokeAllForUserExceptAsync(userId, keep, now, ct); }
        public Task<int> RevokeAllForUserInAppAsync(Guid userId, Guid appId, DateTimeOffset now, CancellationToken ct = default) => inner.RevokeAllForUserInAppAsync(userId, appId, now, ct);
        public Task<int> CapExpiryForUserAsync(Guid userId, DateTimeOffset endsAt, DateTimeOffset now, CancellationToken ct = default) => inner.CapExpiryForUserAsync(userId, endsAt, now, ct);
        public Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default) => inner.PurgeAsync(expiredBefore, ct);
    }

    private sealed class Rig
    {
        public InMemoryUserRepository Users = null!;
        public CredentialHook Creds = null!;
        public FlakySessions Sessions = null!;
        public UserService UserSvc = null!;
        public CredentialService CredSvc = null!;
        public AuthService Auth = null!;
        public SessionService SessionSvc = null!;
        public App Shop = null!;
        public User Alice = null!;
    }

    private static async Task<Rig> Setup(UserKind kind = UserKind.Person)
    {
        var s = new InMemoryStore();
        var r = new Rig { Users = new InMemoryUserRepository(s), Creds = new CredentialHook(new InMemoryCredentialRepository(s)), Sessions = new FlakySessions(new InMemorySessionRepository(s)) };
        var apps = new InMemoryAppRepository(s);
        var roles = new InMemoryRoleRepository(s);
        var hasher = new PlainHasher();
        r.UserSvc = new UserService(r.Users, new AdminGuard(apps, roles, r.Users), r.Sessions, roles);
        r.CredSvc = new CredentialService(r.Users, r.Creds, hasher, null, r.Sessions);
        r.Auth = new AuthService(r.Users, apps, r.Creds, hasher);
        r.SessionSvc = new SessionService(r.Sessions, r.Auth);
        r.Shop = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var buyer = await roles.AddAsync(new Role(Guid.NewGuid(), r.Shop.Id, "buyer", ""));
        r.Alice = await r.UserSvc.CreateAsync("alice", "alice@example.com", null, true, kind, kind == UserKind.Test ? Clock.UtcNowMicros().AddDays(5) : null);
        await r.CredSvc.SetPasswordAsync(r.Alice.Id, Password);
        await r.Users.AssignRoleAsync(r.Alice.Id, buyer.Id);
        return r;
    }

    private static async Task<(Session Session, string Token, AuthResult Auth)> SignIn(Rig r)
    {
        var login = await r.Auth.LoginAsync("alice", Password, "shop") ?? throw new InvalidOperationException("login failed");
        return await r.SessionSvc.StartAsync(login) ?? throw new InvalidOperationException("session refused");
    }

    private static async Task<bool> Counts(Rig r, Session s) => await r.SessionSvc.IsActiveAsync(s.Id);
    private static async Task<bool> Listed(Rig r, Session s) => (await r.Sessions.ListActiveByUserAsync(r.Alice.Id, Clock.UtcNowMicros())).Any(x => x.Id == s.Id);

    // ---- login stamp ----

    [Fact]
    public async Task The_login_stamp_is_taken_before_the_stored_hash_is_read_and_the_session_keeps_it()
    {
        var r = await Setup();
        r.Creds.ClockAtGetHash = null;
        var (session, _, auth) = await SignIn(r);
        Assert.NotNull(r.Creds.ClockAtGetHash);
        Assert.True(auth.AuthenticatedAt <= r.Creds.ClockAtGetHash);
        Assert.Equal(auth.AuthenticatedAt, session.AuthenticatedAt);
        Assert.True(session.AuthenticatedAt <= session.CreatedAt);
        Assert.Equal(session.AuthenticatedAt, (await r.Sessions.GetAsync(session.Id))!.AuthenticatedAt);
    }

    [Fact]
    public async Task A_refresh_keeps_the_original_stamp_and_rotation_does_not_move_it()
    {
        var r = await Setup();
        var (session, token, _) = await SignIn(r);
        var refreshed = await r.SessionSvc.RefreshAsync(token);
        Assert.Null(refreshed.Failure);
        Assert.Equal(session.AuthenticatedAt, refreshed.Auth!.AuthenticatedAt);
        Assert.Equal(session.AuthenticatedAt, refreshed.Session!.AuthenticatedAt);
        Assert.Equal(session.AuthenticatedAt, (await r.Sessions.GetAsync(session.Id))!.AuthenticatedAt);
        Assert.Equal(session.AuthenticatedAt, (await r.SessionSvc.RefreshAsync(refreshed.Token)).Auth!.AuthenticatedAt);
    }

    // ---- login racing a change ----

    public enum Change { AdminPasswordReset, OwnPasswordChange, Deactivation, DeactivationThenReactivation, AdminRevokeAll }

    private static async Task Apply(Rig r, Change change)
    {
        switch (change)
        {
            case Change.AdminPasswordReset: await r.CredSvc.SetPasswordAsync(r.Alice.Id, "another password 99"); break;
            case Change.OwnPasswordChange:
                Assert.Equal(OwnPasswordResult.Changed, (await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, "another password 99", null)).Result);
                break;
            case Change.Deactivation: await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false); break;
            case Change.DeactivationThenReactivation:
                await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false);
                await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, true);
                break;
            case Change.AdminRevokeAll: await r.SessionSvc.RevokeAllAndCutOffAsync(r.Alice.Id); break;
        }
    }

    [Theory]
    [InlineData(Change.AdminPasswordReset)]
    [InlineData(Change.OwnPasswordChange)]
    [InlineData(Change.Deactivation)]
    [InlineData(Change.DeactivationThenReactivation)]
    [InlineData(Change.AdminRevokeAll)]
    public async Task A_login_that_read_the_old_state_cannot_keep_a_session_when_the_change_lands_before_its_insert(Change change)
    {
        var r = await Setup();
        // The login has read the stored hash (the old password) when the change lands; it then verifies it and inserts its session.
        r.Creds.AfterGetHash = () => Apply(r, change);
        var login = await r.Auth.LoginAsync("alice", Password, "shop");
        Assert.NotNull(login); // it read the user and the hash before the change, so its own checks pass

        var started = await r.SessionSvc.StartAsync(login);

        Assert.Null(started); // refused: "raced"
        Assert.Empty(await r.Sessions.ListActiveByUserAsync(r.Alice.Id, Clock.UtcNowMicros()));
    }

    [Theory]
    [InlineData(Change.AdminPasswordReset)]
    [InlineData(Change.OwnPasswordChange)]
    [InlineData(Change.DeactivationThenReactivation)]
    [InlineData(Change.AdminRevokeAll)]
    public async Task A_change_after_the_insert_ends_the_session_too_even_if_it_was_inserted_unrevoked(Change change)
    {
        var r = await Setup();
        var (session, token, _) = await SignIn(r);
        await Apply(r, change);
        Assert.False(await Counts(r, session));
        Assert.False(await Listed(r, session));
        Assert.NotNull((await r.SessionSvc.RefreshAsync(token)).Failure); // "invalid" (row revoked) or "inactive" (cut-off only)
        // and a fresh login after the change works and counts
        var again = await r.Auth.LoginAsync("alice", change is Change.AdminPasswordReset or Change.OwnPasswordChange ? "another password 99" : Password, "shop");
        var (fresh, _, _) = (await r.SessionSvc.StartAsync(again!))!.Value;
        Assert.True(await Counts(r, fresh));
    }

    // ---- partial failures ----

    [Fact]
    public async Task A_reactivation_whose_revoke_step_failed_still_refuses_the_old_sessions()
    {
        var r = await Setup();
        var (session, token, _) = await SignIn(r);
        r.Sessions.FailRevokeAll = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false)); // deactivated, rows not revoked
        Assert.Null((await r.Sessions.GetAsync(session.Id))!.RevokedAt);
        Assert.False(await Counts(r, session));
        r.Sessions.FailRevokeAll = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, true));    // reactivated, rows still not revoked
        Assert.Null((await r.Sessions.GetAsync(session.Id))!.RevokedAt);
        Assert.True((await r.Users.GetAsync(r.Alice.Id))!.IsActive);

        Assert.False(await Counts(r, session));
        Assert.False(await Listed(r, session));
        Assert.Equal("inactive", (await r.SessionSvc.RefreshAsync(token)).Failure);
    }

    [Fact]
    public async Task A_crash_between_the_admin_password_write_and_the_session_revoke_leaves_no_live_session()
    {
        var r = await Setup();
        var (session, token, _) = await SignIn(r);
        r.Sessions.FailRevokeAll = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.CredSvc.SetPasswordAsync(r.Alice.Id, "another password 99"));
        Assert.Equal("h:another password 99", await r.Creds.GetHashAsync(r.Alice.Id)); // the new password is stored
        Assert.False(await Counts(r, session));
        Assert.NotNull((await r.SessionSvc.RefreshAsync(token)).Failure);
    }

    [Fact]
    public async Task A_crash_between_the_own_password_write_and_the_revoke_of_the_others_leaves_only_the_current_session()
    {
        var r = await Setup();
        var (current, _, _) = await SignIn(r);
        var (other, otherToken, _) = await SignIn(r);
        r.Sessions.FailRevokeAllExcept = true;
        await Assert.ThrowsAsync<StoreUnavailableException>(() => r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, "another password 99", current.Id));
        Assert.NotNull((await r.Sessions.GetAsync(other.Id))!.RevokedAt); // ended in the same write as the hash; only the bookkeeping step failed
        Assert.False(await Counts(r, other));
        Assert.NotNull((await r.SessionSvc.RefreshAsync(otherToken)).Failure);
        Assert.True(await Counts(r, current));
    }

    // ---- own password change ----

    [Fact]
    public async Task An_own_password_change_keeps_exactly_the_current_session_and_it_can_still_refresh()
    {
        var r = await Setup();
        var (current, currentToken, _) = await SignIn(r);
        var (other, _, _) = await SignIn(r);
        var (third, _, _) = await SignIn(r);

        var change = await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, "another password 99", current.Id);

        Assert.Equal(OwnPasswordResult.Changed, change.Result);
        Assert.Equal(2, change.SessionsRevoked);
        Assert.NotNull(change.CutOff);
        Assert.True(await Counts(r, current));
        Assert.False(await Counts(r, other));
        Assert.False(await Counts(r, third));
        Assert.Equal([current.Id], (await r.Sessions.ListActiveByUserAsync(r.Alice.Id, Clock.UtcNowMicros())).Select(x => x.Id));
        var user = (await r.Users.GetAsync(r.Alice.Id))!;
        Assert.Equal(change.CutOff, user.SessionsValidAfter);
        var restamp = (await r.Sessions.GetAsync(current.Id))!.AuthenticatedAt!.Value;
        Assert.True(restamp > user.SessionsValidAfter);
        var refreshed = await r.SessionSvc.RefreshAsync(currentToken);
        Assert.Null(refreshed.Failure);
        Assert.Equal(restamp, refreshed.Auth!.AuthenticatedAt);
    }

    [Fact]
    public async Task An_own_password_change_with_a_token_that_has_no_session_ends_every_session()
    {
        var r = await Setup();
        var (a, _, _) = await SignIn(r);
        var (b, _, _) = await SignIn(r);
        var change = await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, "another password 99", null);
        Assert.Equal(2, change.SessionsRevoked);
        Assert.False(await Counts(r, a));
        Assert.False(await Counts(r, b));
    }

    [Fact]
    public async Task A_refused_own_password_change_raises_nothing_and_restamps_nothing()
    {
        var r = await Setup();
        var (current, _, _) = await SignIn(r);
        var stamp = current.AuthenticatedAt;
        Assert.Equal(OwnPasswordResult.WrongCurrent, (await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, "wrong wrong wrong", "another password 99", current.Id)).Result);
        Assert.Equal(OwnPasswordResult.Unchanged, (await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, Password, current.Id)).Result);
        Assert.Null((await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        Assert.Equal(stamp, (await r.Sessions.GetAsync(current.Id))!.AuthenticatedAt);
    }

    // ---- version, first password, no-op ----

    [Fact]
    public async Task Raising_the_cut_off_alone_never_changes_the_version_but_a_deactivation_does_once()
    {
        var r = await Setup();
        var v = (await r.Users.GetAsync(r.Alice.Id))!.Version;
        await r.CredSvc.SetPasswordAsync(r.Alice.Id, "another password 99");
        await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, "another password 99", "third password 333", null);
        await r.SessionSvc.RevokeAllAndCutOffAsync(r.Alice.Id);
        var user = (await r.Users.GetAsync(r.Alice.Id))!;
        Assert.NotNull(user.SessionsValidAfter);
        Assert.Equal(v, user.Version);

        await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false);
        Assert.Equal(v + 1, (await r.Users.GetAsync(r.Alice.Id))!.Version);
        await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, false); // nothing changes: no write, no new cut-off, no version
        var again = (await r.Users.GetAsync(r.Alice.Id))!;
        Assert.Equal(v + 1, again.Version);
    }

    [Fact]
    public async Task A_first_password_leaves_the_cut_off_alone_a_second_one_raises_it()
    {
        var r = await Setup();
        var bob = await r.UserSvc.CreateAsync("bob", "bob@example.com", null);
        Assert.Null(await r.CredSvc.SetPasswordAsync(bob.Id, Password));
        Assert.Null((await r.Users.GetAsync(bob.Id))!.SessionsValidAfter);
        var second = await r.CredSvc.SetPasswordAsync(bob.Id, "another password 99");
        Assert.NotNull(second);
        Assert.Equal(second, (await r.Users.GetAsync(bob.Id))!.SessionsValidAfter);
    }

    [Fact]
    public async Task Editing_other_fields_or_staying_active_does_not_raise_the_cut_off()
    {
        var r = await Setup();
        var (session, _, _) = await SignIn(r);
        await r.UserSvc.PatchAsync(r.Alice.Id, null, "alice2@example.com", "Alice", true);
        await r.UserSvc.UpdateAsync(r.Alice.Id, "alice", "alice2@example.com", "Alice B", null);
        Assert.Null((await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        Assert.True(await Counts(r, session));
    }

    [Fact]
    public async Task The_user_update_reports_the_cut_off_it_raised()
    {
        var r = await Setup();
        var (_, fx) = await r.UserSvc.PatchWithEffectsAsync(r.Alice.Id, null, null, null, false);
        Assert.NotNull(fx.CutOff);
        Assert.Equal(fx.CutOff, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        var (_, none) = await r.UserSvc.PatchWithEffectsAsync(r.Alice.Id, null, null, "x", null);
        Assert.Null(none.CutOff);
    }

    [Fact]
    public async Task An_expired_test_user_who_becomes_usable_again_gets_a_cut_off()
    {
        var r = await Setup(UserKind.Test);
        var (session, _, _) = await SignIn(r);
        // the account expires (the store is written directly, as time passing would)
        var expired = Clock.UtcNowMicros().AddMinutes(-1);
        await r.Users.UpdateAsync((await r.Users.GetAsync(r.Alice.Id))! with { ExpiresAt = expired });
        Assert.False(await Counts(r, session) && (await r.Users.GetAsync(r.Alice.Id))!.IsUsable(Clock.UtcNowMicros()));

        await r.UserSvc.PatchAsync(r.Alice.Id, null, null, null, null, null, Clock.UtcNowMicros().AddDays(3));

        Assert.NotNull((await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter);
        Assert.False(await Counts(r, session));
    }

    // ---- sessions of a token without a session ----

    [Fact]
    public async Task A_login_without_a_session_carries_its_stamp_for_the_token()
    {
        var r = await Setup();
        var login = await r.Auth.LoginAsync("alice", Password, "shop");
        Assert.NotNull(login!.AuthenticatedAt);
        Assert.True(login.AuthenticatedAt <= Clock.UtcNowMicros());
    }

    [Fact]
    public async Task Resolve_with_a_stamp_refuses_a_sign_in_that_is_not_after_the_cut_off()
    {
        var r = await Setup();
        var t = Clock.UtcNowMicros();
        await r.CredSvc.SetPasswordAsync(r.Alice.Id, "another password 99");
        var cut = (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter!.Value;
        Assert.Null(await r.Auth.ResolveAsync(r.Alice.Id, r.Shop.Id, t));
        Assert.Null(await r.Auth.ResolveAsync(r.Alice.Id, r.Shop.Id, cut));
        Assert.NotNull(await r.Auth.ResolveAsync(r.Alice.Id, r.Shop.Id, cut.AddTicks(10)));
        Assert.NotNull(await r.Auth.ResolveAsync(r.Alice.Id, r.Shop.Id)); // no stamp: the plain resolve is unchanged
    }

    [Fact]
    public async Task A_session_of_another_user_is_not_active_for_the_given_owner()
    {
        var r = await Setup();
        var (session, _, _) = await SignIn(r);
        var bob = await r.UserSvc.CreateAsync("bob", "bob@example.com", null);
        Assert.True(await r.SessionSvc.IsActiveAsync(session.Id, (await r.Users.GetAsync(r.Alice.Id))!));
        Assert.False(await r.SessionSvc.IsActiveAsync(session.Id, bob));
    }

    // ---- review round 2 ----

    private static void TickPast(DateTimeOffset t) { while (Clock.UtcNowMicros() <= t) { } }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_login_without_a_session_stamped_after_the_services_clock_read_but_before_the_commit_is_cut_off(bool ownChange)
    {
        var r = await Setup();
        var (current, _, _) = await SignIn(r);
        AuthResult? login = null;
        r.Creds.BeforeWrite = async read =>
        {
            TickPast(read);
            login = await r.Auth.LoginAsync("alice", Password, "shop"); // stamped after the cut-off the service took, verified against the old hash
        };

        if (ownChange) await r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, "another password 99", current.Id);
        else await r.CredSvc.SetPasswordAsync(r.Alice.Id, "another password 99");

        var user = (await r.Users.GetAsync(r.Alice.Id))!;
        Assert.NotNull(login);
        Assert.False(user.CountsAfterCutOff(login.AuthenticatedAt!.Value)); // its token (auth_time) is refused wherever the cut-off is checked
        Assert.False(user.TokenCountsAfterCutOff(login.AuthenticatedAt.Value.ToUnixTimeSeconds()));
        Assert.Null(await r.SessionSvc.StartAsync(login));
    }

    [Fact]
    public async Task A_busy_store_after_the_current_password_was_verified_says_so()
    {
        var r = await Setup();
        r.Creds.FailReplace = new BusyException();
        var busy = await Assert.ThrowsAsync<BusyException>(() => r.CredSvc.ChangeOwnPasswordAsync(r.Alice.Id, Password, "another password 99", null));
        Assert.True(busy.AfterVerification);
        Assert.Equal("h:" + Password, await r.Creds.GetHashAsync(r.Alice.Id));
    }

    [Fact]
    public async Task A_session_ended_by_the_cut_off_shows_as_revoked_no_later_than_its_expiry()
    {
        var r = await Setup();
        var (session, _, _) = await SignIn(r);
        var far = Clock.UtcNowMicros().AddYears(100);
        await r.Users.UpdateAsync((await r.Users.GetAsync(r.Alice.Id))! with { SessionsValidAfter = far });
        var shown = await r.SessionSvc.GetForUserAsync(r.Alice.Id, session.Id);
        Assert.Equal(session.ExpiresAt, shown.RevokedAt); // the cut-off is later than the expiry: min of the two
        var soon = Clock.UtcNowMicros().AddMinutes(1);
        await r.Users.UpdateAsync((await r.Users.GetAsync(r.Alice.Id))! with { SessionsValidAfter = soon });
        Assert.Equal(far, (await r.Users.GetAsync(r.Alice.Id))!.SessionsValidAfter); // never lowered, so it still shows the expiry
    }
}
