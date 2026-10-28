using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 8h: deleting a role ends the sessions that depended on it, in the same step; deleting an application removes its sessions. Both stores.</summary>
public abstract class Slice8hStoreTests : IDisposable
{
    protected abstract (IAppRepository A, IRoleRepository R, IUserRepository U, ISessionRepository S) Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static readonly DateTimeOffset T0 = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = T0.AddHours(1);

    private sealed record World(IAppRepository A, IRoleRepository R, IUserRepository U, ISessionRepository S, App X, App Y, Role X1, Role X2, Role Y1);

    private async Task<World> Seed()
    {
        var (a, r, u, s) = Open();
        var x = await a.AddAsync(new App(Guid.NewGuid(), "app-x"));
        var y = await a.AddAsync(new App(Guid.NewGuid(), "app-y"));
        return new World(a, r, u, s, x, y,
            await r.AddAsync(new Role(Guid.NewGuid(), x.Id, "x1", "")),
            await r.AddAsync(new Role(Guid.NewGuid(), x.Id, "x2", "")),
            await r.AddAsync(new Role(Guid.NewGuid(), y.Id, "y1", "")));
    }

    private static async Task<User> NewUser(World w, string name, params Role[] roles)
    {
        var user = await w.U.AddAsync(new User(Guid.NewGuid(), name, name + "@example.com", name, true, T0, T0));
        foreach (var role in roles) await w.U.AssignRoleAsync(user.Id, role.Id);
        return user;
    }

    private static async Task<Session> NewSession(World w, User u, App app, DateTimeOffset? revoked = null, DateTimeOffset? expires = null)
    {
        var s = new Session(Guid.NewGuid(), u.Id, app.Id, T0, T0, expires ?? T0.AddDays(30), null);
        await w.S.AddAsync(s, Guid.NewGuid().ToString("N"));
        if (revoked is { } at) await w.S.RevokeAsync(s.Id, at);
        return s;
    }

    private static int Count(IReadOnlyList<RevokedSession>? ended) => ended!.Count;

    private static async Task<bool> Alive(World w, Session s) => (await w.S.GetAsync(s.Id)) is { } x && x.IsActive(Now);

    [SkippableFact]
    public async Task Deleting_a_role_ends_only_the_sessions_that_depended_on_it()
    {
        var w = await Seed();
        var onlyX1 = await NewUser(w, "only-x1", w.X1);
        var both = await NewUser(w, "both", w.X1, w.X2);
        var otherRole = await NewUser(w, "x2-only", w.X2);
        var withY = await NewUser(w, "x1-and-y1", w.X1, w.Y1);
        var nobody = await NewUser(w, "no-roles");

        var sOnly = await NewSession(w, onlyX1, w.X);
        var sOnlyInY = await NewSession(w, onlyX1, w.Y);                      // another application: untouched
        var sBoth = await NewSession(w, both, w.X);                           // keeps x2: untouched
        var sOther = await NewSession(w, otherRole, w.X);                     // never held x1: untouched
        var sWithY = await NewSession(w, withY, w.X);                         // y1 is another application's role: ends
        var sWithYInY = await NewSession(w, withY, w.Y);                      // untouched
        var sNobody = await NewSession(w, nobody, w.X);
        var firstRevoke = T0.AddMinutes(10);
        var sRevoked = await NewSession(w, onlyX1, w.X, revoked: firstRevoke); // already ended: keeps its time
        var sExpired = await NewSession(w, onlyX1, w.X, expires: T0.AddMinutes(30)); // already expired: not touched

        var ended = await w.R.DeleteEndingSessionsAsync(w.X1.Id, null, Now);
        Assert.Equal(new[] { (onlyX1.Id, sOnly.Id), (withY.Id, sWithY.Id) }.OrderBy(x => x.Item2), ended!.Select(x => (x.UserId, x.SessionId)).OrderBy(x => x.SessionId));

        Assert.False(await Alive(w, sOnly));
        Assert.Equal(Now, (await w.S.GetAsync(sOnly.Id))!.RevokedAt);
        Assert.False(await Alive(w, sWithY));
        Assert.True(await Alive(w, sOnlyInY));
        Assert.True(await Alive(w, sBoth));
        Assert.True(await Alive(w, sOther));
        Assert.True(await Alive(w, sWithYInY));
        Assert.True(await Alive(w, sNobody));
        Assert.Equal(firstRevoke, (await w.S.GetAsync(sRevoked.Id))!.RevokedAt);
        Assert.Null((await w.S.GetAsync(sExpired.Id))!.RevokedAt);
        Assert.Null(await w.R.GetAsync(w.X1.Id));
        Assert.Empty(await w.U.ListRolesAsync(onlyX1.Id, w.X.Id));
        Assert.Equal(["x2"], (await w.U.ListRolesAsync(both.Id)).Select(r => r.Name).Where(n => n == "x2"));
    }

    [SkippableFact]
    public async Task Deleting_the_other_role_afterwards_ends_the_remaining_sessions()
    {
        var w = await Seed();
        var both = await NewUser(w, "both", w.X1, w.X2);
        var s = await NewSession(w, both, w.X);
        Assert.Equal(0, Count(await w.R.DeleteEndingSessionsAsync(w.X1.Id, null, Now)));
        Assert.True(await Alive(w, s));
        Assert.Equal(1, Count(await w.R.DeleteEndingSessionsAsync(w.X2.Id, null, Now)));
        Assert.False(await Alive(w, s));
    }

    [SkippableFact]
    public async Task Deleting_two_roles_of_one_application_at_once_still_ends_the_sessions_of_users_who_held_both()
    {
        var w = await Seed();
        var sessions = new List<Session>();
        for (var i = 0; i < 20; i++) sessions.Add(await NewSession(w, await NewUser(w, $"both-{i:00}", w.X1, w.X2), w.X));
        var onlyOne = await NewUser(w, "only-x2", w.X2);
        var other = await NewSession(w, onlyOne, w.Y);
        var results = await Task.WhenAll(w.R.DeleteEndingSessionsAsync(w.X1.Id, null, Now), w.R.DeleteEndingSessionsAsync(w.X2.Id, null, Now));
        // however the two deletes interleave, whoever lost both roles has no session left, and each session was ended exactly once
        foreach (var s in sessions) Assert.False(await Alive(w, s));
        Assert.True(await Alive(w, other));
        Assert.Equal(20, results.Sum(r => r!.Count));
        Assert.Equal(20, results.SelectMany(r => r!).Select(x => x.SessionId).Distinct().Count());
        Assert.Null(await w.R.GetAsync(w.X1.Id));
        Assert.Null(await w.R.GetAsync(w.X2.Id));
    }

    [SkippableFact]
    public async Task An_unknown_role_is_null_and_a_wrong_version_changes_nothing()
    {
        var w = await Seed();
        var u = await NewUser(w, "holder", w.X1);
        var s = await NewSession(w, u, w.X);
        Assert.Null(await w.R.DeleteEndingSessionsAsync(Guid.NewGuid(), null, Now));
        Assert.Null(await w.R.DeleteEndingSessionsAsync(Guid.NewGuid(), 3, Now));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => w.R.DeleteEndingSessionsAsync(w.X1.Id, w.X1.Version + 5, Now));
        Assert.NotNull(await w.R.GetAsync(w.X1.Id));
        Assert.True(await Alive(w, s));
        Assert.Equal(1, Count(await w.R.DeleteEndingSessionsAsync(w.X1.Id, w.X1.Version, Now)));
        Assert.False(await Alive(w, s));
    }

    [SkippableFact]
    public async Task Many_holders_are_handled_in_one_call()
    {
        var w = await Seed();
        var sessions = new List<Session>();
        for (var i = 0; i < 300; i++) sessions.Add(await NewSession(w, await NewUser(w, $"holder-{i:000}", w.X1), w.X));
        var keeper = await NewUser(w, "keeper", w.X1, w.X2);
        var kept = await NewSession(w, keeper, w.X);
        Assert.Equal(300, Count(await w.R.DeleteEndingSessionsAsync(w.X1.Id, null, Now)));
        foreach (var s in sessions) Assert.False(await Alive(w, s));
        Assert.True(await Alive(w, kept));
    }

    [SkippableFact]
    public async Task Deleting_an_application_removes_all_its_sessions_and_leaves_other_applications_alone()
    {
        var w = await Seed();
        var u = await NewUser(w, "u", w.X1, w.Y1);
        var v = await NewUser(w, "v");
        var inX = await NewSession(w, u, w.X);
        var inXNoRole = await NewSession(w, v, w.X);
        var revokedInX = await NewSession(w, u, w.X, revoked: T0.AddMinutes(1));
        var inY = await NewSession(w, u, w.Y);
        Assert.True(await w.A.DeleteAsync(w.X.Id));
        foreach (var s in new[] { inX, inXNoRole, revokedInX }) Assert.Null(await w.S.GetAsync(s.Id));
        Assert.True(await Alive(w, inY));
        Assert.Null(await w.R.GetAsync(w.X1.Id));
    }
}

public class InMemorySlice8hStoreTests : Slice8hStoreTests
{
    protected override (IAppRepository, IRoleRepository, IUserRepository, ISessionRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s), new InMemorySessionRepository(s));
    }
}

public class PostgresSlice8hStoreTests : Slice8hStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];

    protected override (IAppRepository, IRoleRepository, IUserRepository, ISessionRepository) Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IRoleRepository>(), p.GetRequiredService<IUserRepository>(), p.GetRequiredService<ISessionRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }
}
