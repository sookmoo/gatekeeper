using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 7a: the per-user session cut-off, same assertions against both stores.</summary>
public abstract class Slice7aStoreTests : IDisposable
{
    protected abstract (IAppRepository A, IUserRepository U, ICredentialRepository C, ISessionRepository S) Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static readonly DateTimeOffset T0 = new(2126, 10, 25, 12, 0, 0, TimeSpan.Zero); // far in the future: the stores raise the cut-off to at least their own clock (7a), which then never exceeds these values

    private async Task<(IUserRepository U, ICredentialRepository C, ISessionRepository S, User User, App App)> Seed()
    {
        var (apps, users, creds, sessions) = Open();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var user = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        return (users, creds, sessions, user, app);
    }

    private static Session NewSession(User u, App a, DateTimeOffset created, DateTimeOffset? stamp = null) =>
        new(Guid.NewGuid(), u.Id, a.Id, created, created, created.AddDays(1), null, stamp);

    [SkippableFact]
    public async Task The_sign_in_stamp_round_trips_and_defaults_to_the_creation_time()
    {
        var (_, _, sessions, u, a) = await Seed();
        var explicitStamp = NewSession(u, a, T0, T0.AddMinutes(-3));
        var implicitStamp = NewSession(u, a, T0.AddMinutes(1));
        await sessions.AddAsync(explicitStamp, "h1");
        await sessions.AddAsync(implicitStamp, "h2");
        Assert.Equal(T0.AddMinutes(-3), (await sessions.GetAsync(explicitStamp.Id))!.AuthenticatedAt);
        Assert.Equal(implicitStamp.CreatedAt, (await sessions.GetAsync(implicitStamp.Id))!.AuthenticatedAt);
        // rotation keeps the stamp
        Assert.True(await sessions.RotateAsync(explicitStamp.Id, "h1", "h1b", T0.AddMinutes(5)));
        Assert.Equal(T0.AddMinutes(-3), (await sessions.GetAsync(explicitStamp.Id))!.AuthenticatedAt);
    }

    [SkippableFact]
    public async Task The_cut_off_only_rises_through_user_updates_and_the_version_follows_only_the_update()
    {
        var (users, _, _, u, _) = await Seed();
        Assert.Null(u.SessionsValidAfter);
        var raised = await users.UpdateAsync(u with { DisplayName = "B", SessionsValidAfter = T0.AddHours(1) }, 1);
        Assert.Equal(2, raised!.Version);
        Assert.Equal(T0.AddHours(1), (await users.GetAsync(u.Id))!.SessionsValidAfter);

        // an older copy (or an older value) never lowers it, whatever else it changes
        var stale = await users.UpdateAsync(u with { DisplayName = "C", SessionsValidAfter = T0.AddMinutes(1) });
        Assert.Equal(3, stale!.Version);
        Assert.Equal(T0.AddHours(1), (await users.GetAsync(u.Id))!.SessionsValidAfter);
        await users.UpdateAsync(u with { DisplayName = "D" }); // a copy that never knew the cut-off
        Assert.Equal(T0.AddHours(1), (await users.GetAsync(u.Id))!.SessionsValidAfter);

        await users.UpdateAsync(u with { SessionsValidAfter = T0.AddHours(2) }, 4);
        Assert.Equal(T0.AddHours(2), (await users.GetAsync(u.Id))!.SessionsValidAfter);
        // a refused conditional update changes nothing, not even the cut-off
        await Assert.ThrowsAsync<PreconditionFailedException>(() => users.UpdateAsync(u with { SessionsValidAfter = T0.AddHours(9) }, 1));
        Assert.Equal(T0.AddHours(2), (await users.GetAsync(u.Id))!.SessionsValidAfter);
    }

    [SkippableFact]
    public async Task Setting_a_password_with_a_cut_off_writes_both_and_leaves_the_version_alone()
    {
        var (users, creds, _, u, _) = await Seed();
        await creds.SetAsync(u.Id, "h1", T0);
        Assert.Null((await users.GetAsync(u.Id))!.SessionsValidAfter); // no cut-off asked: none written

        await creds.SetAsync(u.Id, "h2", T0.AddMinutes(1), T0.AddMinutes(1));
        var after = (await users.GetAsync(u.Id))!;
        Assert.Equal(T0.AddMinutes(1), after.SessionsValidAfter);
        Assert.Equal(1, after.Version);
        Assert.Equal("h2", await creds.GetHashAsync(u.Id));

        await creds.SetAsync(u.Id, "h3", T0.AddMinutes(2), T0.AddSeconds(5)); // an older cut-off does not lower it
        Assert.Equal(T0.AddMinutes(1), (await users.GetAsync(u.Id))!.SessionsValidAfter);

        await Assert.ThrowsAsync<NotFoundException>(() => creds.SetAsync(Guid.NewGuid(), "h", T0, T0));
    }

    [SkippableFact]
    public async Task Sessions_that_do_not_count_after_the_cut_off_are_not_listed_and_not_rotated()
    {
        var (users, creds, sessions, u, a) = await Seed();
        var before = NewSession(u, a, T0.AddMinutes(-10));                 // authenticated before the cut-off
        var raced = NewSession(u, a, T0.AddMinutes(2), T0.AddMinutes(-1));  // created after it, but the sign-in began before it
        var tie = NewSession(u, a, T0.AddMinutes(2), T0);                   // began exactly at the cut-off: does not count
        var after = NewSession(u, a, T0.AddMinutes(3), T0.AddMicroseconds(1));
        foreach (var (s, h) in new[] { (before, "b"), (raced, "r"), (tie, "t"), (after, "a") }) await sessions.AddAsync(s, h);
        await users.UpdateAsync(u with { SessionsValidAfter = T0 }); // cut-off = T0 through a user update: the session rows are not touched

        var now = T0.AddMinutes(10);
        Assert.Equal([after.Id], (await sessions.ListActiveByUserAsync(u.Id, now)).Select(x => x.Id));
        Assert.False(await sessions.RotateAsync(before.Id, "b", "b2", now));
        Assert.False(await sessions.RotateAsync(raced.Id, "r", "r2", now));
        Assert.False(await sessions.RotateAsync(tie.Id, "t", "t2", now));
        Assert.True(await sessions.RotateAsync(after.Id, "a", "a2", now));
        Assert.Null((await sessions.GetAsync(before.Id))!.RevokedAt); // rows are not touched by the cut-off itself
        Assert.Equal(2, (await users.GetAsync(u.Id))!.Version);
    }

    [SkippableFact]
    public async Task Another_users_cut_off_does_not_touch_a_session()
    {
        var (users, creds, sessions, u, a) = await Seed();
        var bob = await users.AddAsync(new User(Guid.NewGuid(), "bob", "bob@example.com", "B", true, T0, T0));
        var bobs = NewSession(bob, a, T0.AddMinutes(-10));
        await sessions.AddAsync(bobs, "b");
        await creds.SetAsync(u.Id, "h", T0, T0);
        Assert.Equal([bobs.Id], (await sessions.ListActiveByUserAsync(bob.Id, T0.AddMinutes(1))).Select(x => x.Id));
        Assert.True(await sessions.RotateAsync(bobs.Id, "b", "b2", T0.AddMinutes(1)));
    }

    [SkippableFact]
    public async Task Replacing_the_hash_with_a_cut_off_keeps_exactly_the_named_session()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "old", T0);
        var keep = NewSession(u, a, T0.AddMinutes(-20));
        var other = NewSession(u, a, T0.AddMinutes(-10));
        var foreign = NewSession(u, a, T0.AddMinutes(-5)) with { RevokedAt = T0.AddMinutes(-4) }; // already ended: not revived
        foreach (var (s, h) in new[] { (keep, "k"), (other, "o"), (foreign, "f") }) await sessions.AddAsync(s, h);

        // a stale expectation changes nothing at all
        Assert.False(await creds.ReplaceHashAsync(u.Id, "not-the-hash", "new", T0, T0, keep.Id));
        Assert.Null((await users.GetAsync(u.Id))!.SessionsValidAfter);
        Assert.Equal(keep.CreatedAt, (await sessions.GetAsync(keep.Id))!.AuthenticatedAt);
        Assert.Equal("old", await creds.GetHashAsync(u.Id));

        Assert.True(await creds.ReplaceHashAsync(u.Id, "old", "new", T0, T0, keep.Id));
        var user = (await users.GetAsync(u.Id))!;
        Assert.Equal(T0, user.SessionsValidAfter);
        Assert.Equal(1, user.Version);
        Assert.Equal("new", await creds.GetHashAsync(u.Id));
        Assert.Equal(T0.AddTicks(10), (await sessions.GetAsync(keep.Id))!.AuthenticatedAt); // one microsecond after the cut-off
        Assert.Equal(other.CreatedAt, (await sessions.GetAsync(other.Id))!.AuthenticatedAt);
        Assert.Equal([keep.Id], (await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(1))).Select(x => x.Id));
        Assert.True(await sessions.RotateAsync(keep.Id, "k", "k2", T0.AddMinutes(1)));
        Assert.False(await sessions.RotateAsync(other.Id, "o", "o2", T0.AddMinutes(1)));
    }

    [SkippableFact]
    public async Task Replacing_the_hash_without_a_cut_off_changes_only_the_hash()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "old", T0);
        var s = NewSession(u, a, T0.AddMinutes(-5));
        await sessions.AddAsync(s, "h");
        Assert.True(await creds.ReplaceHashAsync(u.Id, "old", "rehashed", T0));
        Assert.Null((await users.GetAsync(u.Id))!.SessionsValidAfter);
        Assert.Equal([s.Id], (await sessions.ListActiveByUserAsync(u.Id, T0)).Select(x => x.Id));
    }

    [SkippableFact]
    public async Task A_kept_session_that_is_not_the_users_or_not_active_is_not_restamped()
    {
        var (users, creds, sessions, u, a) = await Seed();
        var bob = await users.AddAsync(new User(Guid.NewGuid(), "bob", "bob@example.com", "B", true, T0, T0));
        await creds.SetAsync(u.Id, "old", T0);
        var bobs = NewSession(bob, a, T0.AddMinutes(-5));
        var expired = NewSession(u, a, T0.AddDays(-3)) with { ExpiresAt = T0.AddDays(-2) };
        await sessions.AddAsync(bobs, "b");
        await sessions.AddAsync(expired, "e");
        Assert.True(await creds.ReplaceHashAsync(u.Id, "old", "new", T0, T0, bobs.Id));
        Assert.Equal(bobs.CreatedAt, (await sessions.GetAsync(bobs.Id))!.AuthenticatedAt);
        await creds.SetAsync(u.Id, "old2", T0);
        Assert.True(await creds.ReplaceHashAsync(u.Id, "old2", "new2", T0.AddMinutes(1), T0.AddMinutes(1), expired.Id));
        Assert.Equal(expired.CreatedAt, (await sessions.GetAsync(expired.Id))!.AuthenticatedAt);
    }

    [SkippableFact]
    public async Task Revoke_all_and_cut_off_revokes_the_rows_raises_the_cut_off_and_keeps_the_version()
    {
        var (users, _, sessions, u, a) = await Seed();
        var one = NewSession(u, a, T0.AddMinutes(-5));
        var two = NewSession(u, a, T0.AddMinutes(-4));
        var ended = NewSession(u, a, T0.AddMinutes(-3)) with { RevokedAt = T0.AddMinutes(-2) };
        foreach (var (s, h) in new[] { (one, "1"), (two, "2"), (ended, "3") }) await sessions.AddAsync(s, h);

        Assert.Equal(0, await sessions.RevokeAllAndCutOffAsync(Guid.NewGuid(), T0)); // unknown user: nothing
        Assert.Equal(2, await sessions.RevokeAllAndCutOffAsync(u.Id, T0));
        var user = (await users.GetAsync(u.Id))!;
        Assert.Equal(T0, user.SessionsValidAfter);
        Assert.Equal(1, user.Version);
        Assert.Equal(T0, (await sessions.GetAsync(one.Id))!.RevokedAt);
        Assert.Equal(T0.AddMinutes(-2), (await sessions.GetAsync(ended.Id))!.RevokedAt);

        // repeating with an older time never lowers the cut-off; a session whose sign-in began after it counts
        Assert.Equal(0, await sessions.RevokeAllAndCutOffAsync(u.Id, T0.AddSeconds(-30)));
        Assert.Equal(T0, (await users.GetAsync(u.Id))!.SessionsValidAfter);
        var fresh = NewSession(u, a, T0.AddMinutes(1));
        await sessions.AddAsync(fresh, "f");
        Assert.Equal([fresh.Id], (await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(2))).Select(x => x.Id));
    }

    [SkippableFact]
    public async Task A_user_update_that_raises_the_cut_off_and_a_parallel_raise_never_lower_it()
    {
        var (users, creds, _, u, _) = await Seed();
        await creds.SetAsync(u.Id, "h", T0);
        var tasks = Enumerable.Range(1, 12).SelectMany(i => new[]
        {
            Task.Run(() => creds.SetAsync(u.Id, "h", T0, T0.AddMinutes(i))),
            Task.Run(async () => await users.UpdateAsync(u with { DisplayName = "n" + i, SessionsValidAfter = T0.AddMinutes(100 + i) })),
        }).ToArray();
        await Task.WhenAll(tasks);
        Assert.Equal(T0.AddMinutes(112), (await users.GetAsync(u.Id))!.SessionsValidAfter);
    }
}

public class InMemorySlice7aStoreTests : Slice7aStoreTests
{
    protected override (IAppRepository, IUserRepository, ICredentialRepository, ISessionRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryUserRepository(s), new InMemoryCredentialRepository(s), new InMemorySessionRepository(s));
    }
}

public class PostgresSlice7aStoreTests : Slice7aStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];

    protected override (IAppRepository, IUserRepository, ICredentialRepository, ISessionRepository) Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IUserRepository>(), p.GetRequiredService<ICredentialRepository>(), p.GetRequiredService<ISessionRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }
}
