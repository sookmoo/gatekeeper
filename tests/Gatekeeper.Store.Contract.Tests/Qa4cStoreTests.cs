using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>QA slice 4c: session repository edge cases, same assertions against both stores.</summary>
public abstract class Qa4cStoreTests : IDisposable
{
    protected abstract (IAppRepository A, IUserRepository U, ISessionRepository S) Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static readonly DateTimeOffset T0 = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    private async Task<(ISessionRepository S, User U, App A)> Seed()
    {
        var (apps, users, s) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var u = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        return (s, u, a);
    }

    [SkippableFact]
    public async Task Revoke_for_user_only_touches_a_session_of_that_user()
    {
        var (s, u, a) = await Seed();
        var (_, users, _) = Open();
        var other = await users.AddAsync(new User(Guid.NewGuid(), "bob", "bob@example.com", "B", true, T0, T0));
        var mine = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        await s.AddAsync(mine, "m");
        var at = T0.AddHours(1);
        Assert.False(await s.RevokeForUserAsync(other.Id, mine.Id, at));            // not this user's: unchanged
        Assert.Null((await s.GetAsync(mine.Id))!.RevokedAt);
        Assert.False(await s.RevokeForUserAsync(u.Id, Guid.NewGuid(), at));        // unknown session
        Assert.True(await s.RevokeForUserAsync(u.Id, mine.Id, at));
        Assert.True(await s.RevokeForUserAsync(u.Id, mine.Id, at.AddHours(1)));    // idempotent, keeps the first time
        Assert.Equal(at, (await s.GetAsync(mine.Id))!.RevokedAt);
    }

    [SkippableFact]
    public async Task Rotation_and_activity_are_exclusive_at_the_exact_expiry_instant()
    {
        var (s, u, a) = await Seed();
        var x = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        await s.AddAsync(x, "h1");
        Assert.True(x.IsActive(x.ExpiresAt - TimeSpan.FromTicks(10)));
        Assert.False(x.IsActive(x.ExpiresAt));
        Assert.False(await s.RotateAsync(x.Id, "h1", "h2", x.ExpiresAt));
        Assert.Single(await s.ListActiveByUserAsync(u.Id, x.ExpiresAt - TimeSpan.FromMicroseconds(1)));
        Assert.Empty(await s.ListActiveByUserAsync(u.Id, x.ExpiresAt));
        Assert.True(await s.RotateAsync(x.Id, "h1", "h2", x.ExpiresAt - TimeSpan.FromMicroseconds(1)));
    }

    [SkippableFact]
    public async Task Parallel_rotations_of_the_same_hash_have_exactly_one_winner()
    {
        var (s, u, a) = await Seed();
        var x = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        await s.AddAsync(x, "h1");
        var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(i => Task.Run(() => s.RotateAsync(x.Id, "h1", "n" + i, T0.AddMinutes(1)))));
        Assert.Equal(1, results.Count(r => r));
        var h = (await s.GetHashesAsync(x.Id))!;
        Assert.Equal("h1", h.Previous);
    }

    [SkippableFact]
    public async Task Revoke_all_skips_expired_and_purge_boundary_is_exclusive()
    {
        var (s, u, a) = await Seed();
        var live = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        var dead = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddHours(1), null);
        await s.AddAsync(live, "l"); await s.AddAsync(dead, "d");
        Assert.Equal(1, await s.RevokeAllForUserAsync(u.Id, T0.AddHours(2)));
        Assert.Null((await s.GetAsync(dead.Id))!.RevokedAt);
        Assert.Equal(0, await s.PurgeAsync(dead.ExpiresAt));      // expired exactly then: not older than the limit
        Assert.Equal(1, await s.PurgeAsync(dead.ExpiresAt.AddTicks(10)));
        Assert.Null(await s.GetAsync(dead.Id));
        Assert.NotNull(await s.GetAsync(live.Id));
    }

    [SkippableFact]
    public async Task Revoke_in_one_application_leaves_other_applications_and_users_alone()
    {
        var (apps, users, s) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var b = await apps.AddAsync(new App(Guid.NewGuid(), "blog"));
        var u = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        var v = await users.AddAsync(new User(Guid.NewGuid(), "bob", "bob@example.com", "B", true, T0, T0));
        var inA = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        var inA2 = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        var expiredInA = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddHours(1), null);
        var inB = new Session(Guid.NewGuid(), u.Id, b.Id, T0, T0, T0.AddDays(1), null);
        var otherUser = new Session(Guid.NewGuid(), v.Id, a.Id, T0, T0, T0.AddDays(1), null);
        foreach (var x in new[] { inA, inA2, expiredInA, inB, otherUser }) await s.AddAsync(x, "h" + x.Id);
        var now = T0.AddHours(2);
        Assert.Equal(2, await s.RevokeAllForUserInAppAsync(u.Id, a.Id, now));
        Assert.Equal(0, await s.RevokeAllForUserInAppAsync(u.Id, a.Id, now));
        Assert.Equal(now, (await s.GetAsync(inA.Id))!.RevokedAt);
        Assert.Null((await s.GetAsync(expiredInA.Id))!.RevokedAt);
        Assert.Null((await s.GetAsync(inB.Id))!.RevokedAt);
        Assert.Null((await s.GetAsync(otherUser.Id))!.RevokedAt);
        Assert.Equal(0, await s.RevokeAllForUserInAppAsync(u.Id, Guid.NewGuid(), now));
    }

    [SkippableFact]
    public async Task Cap_expiry_only_shortens_active_sessions_of_that_user()
    {
        var (apps, users, s) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var u = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        var v = await users.AddAsync(new User(Guid.NewGuid(), "bob", "bob@example.com", "B", true, T0, T0));
        var longer = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(10), null);
        var shorter = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddHours(5), null);
        var expired = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddHours(1), null);
        var revoked = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(10), T0.AddMinutes(1));
        var other = new Session(Guid.NewGuid(), v.Id, a.Id, T0, T0, T0.AddDays(10), null);
        foreach (var x in new[] { longer, shorter, expired, revoked, other }) await s.AddAsync(x, "h" + x.Id);
        var now = T0.AddHours(2);
        var ends = T0.AddHours(8);
        Assert.Equal(1, await s.CapExpiryForUserAsync(u.Id, ends, now));
        Assert.Equal(ends, (await s.GetAsync(longer.Id))!.ExpiresAt);
        Assert.Equal(shorter.ExpiresAt, (await s.GetAsync(shorter.Id))!.ExpiresAt);   // never lengthened
        Assert.Equal(expired.ExpiresAt, (await s.GetAsync(expired.Id))!.ExpiresAt);
        Assert.Equal(revoked.ExpiresAt, (await s.GetAsync(revoked.Id))!.ExpiresAt);
        Assert.Equal(other.ExpiresAt, (await s.GetAsync(other.Id))!.ExpiresAt);
        Assert.Equal(0, await s.CapExpiryForUserAsync(u.Id, ends, now));                // idempotent
        Assert.Equal(0, await s.CapExpiryForUserAsync(u.Id, T0.AddDays(30), now));      // a later date changes nothing
        Assert.Equal(ends, (await s.GetAsync(longer.Id))!.ExpiresAt);
    }

    [SkippableFact]
    public async Task Adding_a_session_with_an_existing_id_is_rejected_the_same_way()
    {
        var (s, u, a) = await Seed();
        var x = new Session(Guid.NewGuid(), u.Id, a.Id, T0, T0, T0.AddDays(1), null);
        await s.AddAsync(x, "h1");
        await Assert.ThrowsAnyAsync<Exception>(() => s.AddAsync(x, "OTHER"));
        Assert.Equal("h1", (await s.GetHashesAsync(x.Id))!.Current); // the first token must not be overwritten
    }

    [SkippableFact]
    public async Task Sessions_created_in_the_same_instant_are_listed_in_the_same_order_in_both_stores()
    {
        var (s, u, a) = await Seed();
        var ids = Enumerable.Range(0, 12).Select(_ => Guid.NewGuid()).ToList();
        foreach (var id in ids) await s.AddAsync(new Session(id, u.Id, a.Id, T0, T0, T0.AddDays(1), null), id.ToString());
        var got = (await s.ListActiveByUserAsync(u.Id, T0)).Select(x => x.Id).ToList();
        // Postgres orders uuids bytewise (= their hex text); the in-memory store must agree.
        Assert.Equal(ids.OrderByDescending(g => g.ToString("D"), StringComparer.Ordinal).ToList(), got);
    }
}

public class InMemoryQa4cStoreTests : Qa4cStoreTests
{
    protected override (IAppRepository, IUserRepository, ISessionRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryUserRepository(s), new InMemorySessionRepository(s));
    }
}

public class PostgresQa4cStoreTests : Qa4cStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];

    protected override (IAppRepository, IUserRepository, ISessionRepository) Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IUserRepository>(), p.GetRequiredService<ISessionRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }
}
