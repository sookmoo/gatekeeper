using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>QA for slice 7a: edges of the cut-off contract, same assertions against both stores.</summary>
public abstract class Slice7aQaStoreTests : IDisposable
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
    public async Task The_tie_rule_holds_in_list_and_rotate_a_stamp_equal_to_the_cut_off_does_not_count()
    {
        var (users, _, sessions, u, a) = await Seed();
        var tie = NewSession(u, a, T0.AddMinutes(-5), T0);
        var after = NewSession(u, a, T0.AddMinutes(-4), T0.AddTicks(10));
        var before = NewSession(u, a, T0.AddMinutes(-3), T0.AddTicks(-10));
        foreach (var (s, h) in new[] { (tie, "t"), (after, "a"), (before, "b") }) await sessions.AddAsync(s, h);
        await users.UpdateAsync((await users.GetAsync(u.Id))! with { SessionsValidAfter = T0 });

        Assert.Equal([after.Id], (await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(1))).Select(x => x.Id));
        Assert.False(await sessions.RotateAsync(tie.Id, "t", "t2", T0.AddMinutes(1)));
        Assert.False(await sessions.RotateAsync(before.Id, "b", "b2", T0.AddMinutes(1)));
        Assert.True(await sessions.RotateAsync(after.Id, "a", "a2", T0.AddMinutes(1)));
    }

    [SkippableFact]
    public async Task Keeping_a_session_never_revives_one_the_cut_off_already_ended()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "old", T0);
        var dead = NewSession(u, a, T0.AddMinutes(-20)); // row not revoked, but its sign-in is older than the cut-off below
        await sessions.AddAsync(dead, "d");
        await users.UpdateAsync((await users.GetAsync(u.Id))! with { SessionsValidAfter = T0.AddMinutes(10) });
        Assert.Empty(await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(1)));

        Assert.True(await creds.ReplaceHashAsync(u.Id, "old", "new", T0.AddMinutes(11), T0.AddMinutes(11), dead.Id));

        Assert.Empty(await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(12))); // it must stay ended
        Assert.False(await sessions.RotateAsync(dead.Id, "d", "d2", T0.AddMinutes(12)));
    }

    [SkippableFact]
    public async Task Keeping_a_session_never_lowers_its_stamp()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "old", T0);
        var newer = NewSession(u, a, T0.AddHours(2)); // signed in after the (older) cut-off value this change carries
        await sessions.AddAsync(newer, "n");
        await users.UpdateAsync((await users.GetAsync(u.Id))! with { SessionsValidAfter = T0.AddHours(1) });
        Assert.Equal([newer.Id], (await sessions.ListActiveByUserAsync(u.Id, T0.AddHours(3))).Select(x => x.Id));

        // a change whose cut-off value is older than the stored one (a slow writer) must not turn the kept session into a dead one
        Assert.True(await creds.ReplaceHashAsync(u.Id, "old", "new", T0.AddMinutes(30), T0.AddMinutes(30), newer.Id));

        Assert.Equal(T0.AddHours(1), (await users.GetAsync(u.Id))!.SessionsValidAfter);
        Assert.Equal([newer.Id], (await sessions.ListActiveByUserAsync(u.Id, T0.AddHours(3))).Select(x => x.Id));
        Assert.True((await sessions.GetAsync(newer.Id))!.AuthenticatedAt >= newer.CreatedAt);
    }

    [SkippableFact]
    public async Task Set_with_a_cut_off_for_an_unknown_user_is_not_found_and_changes_nothing()
    {
        var (_, creds, _, _, _) = await Seed();
        var ghost = Guid.NewGuid();
        await Assert.ThrowsAsync<NotFoundException>(() => creds.SetAsync(ghost, "h", T0, T0));
        Assert.Null(await creds.GetHashAsync(ghost));
    }

    [SkippableFact]
    public async Task Replace_with_a_cut_off_on_a_lost_compare_changes_neither_the_cut_off_nor_the_stamp()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "old", T0);
        var s = NewSession(u, a, T0.AddMinutes(-5));
        await sessions.AddAsync(s, "s");
        Assert.False(await creds.ReplaceHashAsync(u.Id, "somebody-else", "new", T0, T0.AddMinutes(1), s.Id));
        Assert.Null((await users.GetAsync(u.Id))!.SessionsValidAfter);
        Assert.Equal(s.CreatedAt, (await sessions.GetAsync(s.Id))!.AuthenticatedAt);
        Assert.Equal("old", await creds.GetHashAsync(u.Id));
    }

    [SkippableFact]
    public async Task Deleting_a_user_removes_the_cut_off_with_it_and_sessions_of_a_new_user_with_the_same_name_are_unaffected()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "h", T0, T0.AddHours(1));
        Assert.True(await users.DeleteAsync(u.Id));
        var again = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        Assert.Null((await users.GetAsync(again.Id))!.SessionsValidAfter);
        var s = NewSession(again, a, T0);
        await sessions.AddAsync(s, "x");
        Assert.Single(await sessions.ListActiveByUserAsync(again.Id, T0.AddMinutes(1)));
    }

    [SkippableFact]
    public async Task Concurrent_logins_inserting_sessions_while_revoke_all_runs_leave_only_post_cut_off_sessions_listed()
    {
        var (users, _, sessions, u, a) = await Seed();
        var cut = T0.AddMinutes(10);
        var inserts = Enumerable.Range(0, 12).Select(i => Task.Run(() =>
            sessions.AddAsync(NewSession(u, a, T0.AddMinutes(i - 6), T0.AddMinutes(i - 6)), "h" + i))).ToList();
        var revoke = Task.Run(() => sessions.RevokeAllAndCutOffAsync(u.Id, cut));
        await Task.WhenAll(inserts);
        await revoke;
        // every session stamped before the cut-off is dead whichever way the race went (revoked by the statement, or refused by the cut-off)
        Assert.Empty(await sessions.ListActiveByUserAsync(u.Id, cut.AddMinutes(1)));
    }
}

public class InMemorySlice7aQaStoreTests : Slice7aQaStoreTests
{
    protected override (IAppRepository, IUserRepository, ICredentialRepository, ISessionRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryUserRepository(s), new InMemoryCredentialRepository(s), new InMemorySessionRepository(s));
    }
}

public class PostgresSlice7aQaStoreTests : Slice7aQaStoreTests
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
