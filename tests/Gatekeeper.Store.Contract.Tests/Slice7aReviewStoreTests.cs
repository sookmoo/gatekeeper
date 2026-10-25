using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 7a review round: the credential-checked session insert, the store-side "first password" rule, and the insert racing a password change.</summary>
public abstract class Slice7aReviewStoreTests : IDisposable
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

    private static Session NewSession(User u, App a, DateTimeOffset at) => new(Guid.NewGuid(), u.Id, a.Id, at, at, at.AddDays(1), null, at);

    [SkippableFact]
    public async Task A_session_is_only_inserted_while_the_verified_hash_is_still_the_stored_one()
    {
        var (_, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "old", T0);
        var ok = NewSession(u, a, T0.AddMinutes(1));
        Assert.True(await sessions.AddForCredentialAsync(ok, "h", "old"));
        Assert.NotNull(await sessions.GetAsync(ok.Id));

        await creds.SetAsync(u.Id, "new", T0.AddMinutes(2));
        var stale = NewSession(u, a, T0.AddMinutes(3));
        Assert.False(await sessions.AddForCredentialAsync(stale, "h2", "old"));
        Assert.Null(await sessions.GetAsync(stale.Id));
        Assert.False(await sessions.AddForCredentialAsync(NewSession(new User(Guid.NewGuid(), "x", "x@x", "", true, T0, T0), a, T0), "h3", "old")); // no credential at all
    }

    [SkippableFact]
    public async Task The_store_decides_that_a_first_password_raises_nothing_and_a_later_one_does()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "first", T0, T0);
        Assert.Null((await users.GetAsync(u.Id))!.SessionsValidAfter);
        var s = NewSession(u, a, T0.AddMinutes(-1));
        await sessions.AddAsync(s, "h");
        await creds.SetAsync(u.Id, "second", T0.AddMinutes(1), T0.AddMinutes(1));
        Assert.Equal(T0.AddMinutes(1), (await users.GetAsync(u.Id))!.SessionsValidAfter);
        Assert.NotNull((await sessions.GetAsync(s.Id))!.RevokedAt); // revoked in the same write
    }

    [SkippableFact]
    public async Task A_user_update_that_passes_the_stored_cut_off_back_is_not_a_raise()
    {
        var (users, creds, sessions, u, a) = await Seed();
        await creds.SetAsync(u.Id, "a", T0);
        await creds.SetAsync(u.Id, "b", T0, T0.AddMinutes(5));
        var kept = NewSession(u, a, T0.AddMinutes(6));
        await sessions.AddAsync(kept, "k");
        var read = (await users.GetAsync(u.Id))!;
        await users.UpdateAsync(read with { DisplayName = "x" }, read.Version);
        Assert.Equal(T0.AddMinutes(5), (await users.GetAsync(u.Id))!.SessionsValidAfter);
        Assert.Equal([kept.Id], (await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(7))).Select(x => x.Id));
    }

    [SkippableFact]
    public async Task A_change_raises_the_cut_off_to_at_least_the_stores_own_clock_and_the_kept_session_survives()
    {
        var (users, creds, sessions, u, a) = await Seed();
        var longAgo = DateTimeOffset.UtcNow.AddMinutes(-30);
        await creds.SetAsync(u.Id, "a", longAgo);
        var keep = NewSession(u, a, longAgo.AddMinutes(-5));
        await sessions.AddAsync(keep, "k");
        var before = DateTimeOffset.UtcNow;
        Assert.True(await creds.ReplaceHashAsync(u.Id, "a", "b", longAgo, longAgo, keep.Id)); // the caller's reading is stale
        var cut = (await users.GetAsync(u.Id))!.SessionsValidAfter!.Value;
        Assert.True(cut >= before.AddTicks(-10), $"{cut:O} should be at least {before:O}");
        Assert.True((await sessions.GetAsync(keep.Id))!.AuthenticatedAt > cut);
        Assert.Equal([keep.Id], (await sessions.ListActiveByUserAsync(u.Id, DateTimeOffset.UtcNow)).Select(x => x.Id));
        var before2 = DateTimeOffset.UtcNow;
        await creds.SetAsync(u.Id, "c", longAgo, longAgo);
        Assert.True((await users.GetAsync(u.Id))!.SessionsValidAfter >= before2.AddTicks(-10));
    }

    [SkippableFact]
    public async Task A_login_insert_racing_a_password_change_never_leaves_a_live_session()
    {
        for (var round = 0; round < 25; round++)
        {
            var (_, creds, sessions, u, a) = await Seed();
            await creds.SetAsync(u.Id, "old", T0);
            var s = NewSession(u, a, T0.AddMinutes(1));
            var insert = Task.Run(async () => { try { return await sessions.AddForCredentialAsync(s, "h", "old"); } catch (BusyException) { return false; } });
            var change = Task.Run(() => creds.SetAsync(u.Id, "new", T0.AddMinutes(1), T0.AddMinutes(1).AddTicks(-10))); // a cut-off that does NOT cover the new session's stamp
            await Task.WhenAll(insert, change);
            // either the insert was refused, or it landed first and the change revoked it: no counting, unrevoked session remains
            Assert.Empty(await sessions.ListActiveByUserAsync(u.Id, T0.AddMinutes(2)));
        }
    }
}

public class InMemorySlice7aReviewStoreTests : Slice7aReviewStoreTests
{
    protected override (IAppRepository, IUserRepository, ICredentialRepository, ISessionRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryUserRepository(s), new InMemoryCredentialRepository(s), new InMemorySessionRepository(s));
    }
}

public class PostgresSlice7aReviewStoreTests : Slice7aReviewStoreTests
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
