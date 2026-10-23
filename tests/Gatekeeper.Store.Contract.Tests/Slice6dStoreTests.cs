using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 6d: row versions and conditional writes, same assertions against both stores.</summary>
public abstract class Slice6dStoreTests : IDisposable
{
    protected sealed record Repos(
        IAppRepository Apps, IRoleRepository Roles, IUserRepository Users, IClientRepository Clients, ICredentialRepository Credentials);

    protected abstract Repos Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static readonly DateTimeOffset T0 = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    private sealed record Seeded(Repos R, App App, Role Role, User User, Client Client);

    private async Task<Seeded> Seed()
    {
        var r = Open();
        var app = await r.Apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var role = await r.Roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "reader", ""));
        var user = await r.Users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        var client = await r.Clients.AddAsync(new Client(Guid.NewGuid(), "checkout", app.Id, true, T0, T0), "hash");
        return new Seeded(r, app, role, user, client);
    }

    [SkippableFact]
    public async Task A_new_row_has_version_one_and_every_update_adds_one_whatever_the_entity_carries()
    {
        var r = Open();
        var app = await r.Apps.AddAsync(new App(Guid.NewGuid(), "shop", 42));
        var role = await r.Roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "reader", "", 42));
        var user = await r.Users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0, Version: 42));
        var client = await r.Clients.AddAsync(new Client(Guid.NewGuid(), "checkout", app.Id, true, T0, T0, 42), "h");
        Assert.Equal([1L, 1, 1, 1], [app.Version, role.Version, user.Version, client.Version]);
        Assert.Equal(1, (await r.Apps.GetAsync(app.Id))!.Version);
        Assert.Equal(1, (await r.Roles.GetAsync(role.Id))!.Version);
        Assert.Equal(1, (await r.Users.GetAsync(user.Id))!.Version);
        Assert.Equal(1, (await r.Clients.GetAsync(client.Id))!.Version);

        // an invented version on the entity is ignored: the store counts
        var a2 = await r.Apps.UpdateAsync(app with { Name = "shop2", Version = 7 });
        var r2 = await r.Roles.UpdateAsync(role with { Name = "reader2", Version = 7 });
        var u2 = await r.Users.UpdateAsync(user with { DisplayName = "B", Version = 7 });
        var c2 = await r.Clients.UpdateAsync(client with { Name = "checkout2", Version = 7 });
        Assert.Equal([2L, 2, 2, 2], [a2!.Version, r2!.Version, u2!.Version, c2!.Version]);
        Assert.Equal(("shop2", 2), ((await r.Apps.GetAsync(app.Id))!.Name, (await r.Apps.GetAsync(app.Id))!.Version));
        Assert.Equal(("reader2", 2), ((await r.Roles.GetAsync(role.Id))!.Name, (await r.Roles.GetAsync(role.Id))!.Version));
        Assert.Equal(("B", 2), ((await r.Users.GetAsync(user.Id))!.DisplayName, (await r.Users.GetAsync(user.Id))!.Version));
        Assert.Equal(("checkout2", 2), ((await r.Clients.GetAsync(client.Id))!.Name, (await r.Clients.GetAsync(client.Id))!.Version));
        // updating again, unconditionally, adds one more
        Assert.Equal(3, (await r.Apps.UpdateAsync(a2, null))!.Version);
        Assert.Equal(3, (await r.Clients.UpdateAsync(c2))!.Version);
    }

    [SkippableFact]
    public async Task An_update_with_the_current_version_succeeds_and_a_stale_one_changes_nothing()
    {
        var s = await Seed();
        var r = s.R;
        Assert.Equal(2, (await r.Apps.UpdateAsync(s.App with { Name = "shop2" }, 1))!.Version);
        Assert.Equal(2, (await r.Roles.UpdateAsync(s.Role with { Name = "reader2" }, 1))!.Version);
        Assert.Equal(2, (await r.Users.UpdateAsync(s.User with { DisplayName = "B" }, 1))!.Version);
        Assert.Equal(2, (await r.Clients.UpdateAsync(s.Client with { Name = "checkout2" }, 1))!.Version);

        // the same expectation again is now stale (and so is one from the future)
        foreach (var stale in new long[] { 1, 3 })
        {
            await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Apps.UpdateAsync(s.App with { Name = "nope" }, stale));
            await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Roles.UpdateAsync(s.Role with { Name = "nope" }, stale));
            await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Users.UpdateAsync(s.User with { DisplayName = "nope" }, stale));
            await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Clients.UpdateAsync(s.Client with { Name = "nope" }, stale));
        }
        Assert.Equal(("shop2", 2), ((await r.Apps.GetAsync(s.App.Id))!.Name, (await r.Apps.GetAsync(s.App.Id))!.Version));
        Assert.Equal(("reader2", 2), ((await r.Roles.GetAsync(s.Role.Id))!.Name, (await r.Roles.GetAsync(s.Role.Id))!.Version));
        Assert.Equal(("B", 2), ((await r.Users.GetAsync(s.User.Id))!.DisplayName, (await r.Users.GetAsync(s.User.Id))!.Version));
        Assert.Equal(("checkout2", 2), ((await r.Clients.GetAsync(s.Client.Id))!.Name, (await r.Clients.GetAsync(s.Client.Id))!.Version));
    }

    [SkippableFact]
    public async Task A_missing_row_wins_over_a_wrong_version_and_a_version_mismatch_wins_over_a_uniqueness_conflict()
    {
        var s = await Seed();
        var r = s.R;
        // missing rows: null / false, never a precondition failure
        Assert.Null(await r.Apps.UpdateAsync(new App(Guid.NewGuid(), "x"), 5));
        Assert.Null(await r.Roles.UpdateAsync(new Role(Guid.NewGuid(), s.App.Id, "x", ""), 5));
        Assert.Null(await r.Users.UpdateAsync(new User(Guid.NewGuid(), "x", "x@example.com", "", true, T0, T0), 5));
        Assert.Null(await r.Clients.UpdateAsync(new Client(Guid.NewGuid(), "x", s.App.Id, true, T0, T0), 5));
        Assert.False(await r.Apps.DeleteAsync(Guid.NewGuid(), 5));
        Assert.False(await r.Roles.DeleteAsync(Guid.NewGuid(), 5));
        Assert.False(await r.Users.DeleteAsync(Guid.NewGuid(), 5));
        Assert.False(await r.Clients.DeleteAsync(Guid.NewGuid(), 5));

        // a name that is taken: the current version gets the conflict, a stale one gets the precondition failure
        var other = await r.Apps.AddAsync(new App(Guid.NewGuid(), "blog"));
        await Assert.ThrowsAsync<ConflictException>(() => r.Apps.UpdateAsync(other with { Name = "shop" }, 1));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Apps.UpdateAsync(other with { Name = "shop" }, 9));
        var bob = await r.Users.AddAsync(new User(Guid.NewGuid(), "bob", "bob@example.com", "", true, T0, T0));
        await Assert.ThrowsAsync<ConflictException>(() => r.Users.UpdateAsync(bob with { Username = "alice" }, 1));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Users.UpdateAsync(bob with { Username = "alice" }, 9));
        Assert.Equal(1, (await r.Apps.GetAsync(other.Id))!.Version); // a refused write does not bump
        Assert.Equal(1, (await r.Users.GetAsync(bob.Id))!.Version);
    }

    [SkippableFact]
    public async Task A_conditional_delete_needs_the_current_version()
    {
        var s = await Seed();
        var r = s.R;
        await r.Roles.UpdateAsync(s.Role with { Description = "d" }); // version 2
        await r.Users.UpdateAsync(s.User with { DisplayName = "B" });
        await r.Clients.UpdateAsync(s.Client with { Name = "checkout2" });
        await r.Apps.UpdateAsync(s.App with { Name = "shop2" });

        await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Roles.DeleteAsync(s.Role.Id, 1));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Users.DeleteAsync(s.User.Id, 1));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Clients.DeleteAsync(s.Client.Id, 1));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => r.Apps.DeleteAsync(s.App.Id, 1));
        Assert.NotNull(await r.Roles.GetAsync(s.Role.Id));
        Assert.NotNull(await r.Users.GetAsync(s.User.Id));
        Assert.NotNull(await r.Clients.GetAsync(s.Client.Id));
        Assert.NotNull(await r.Apps.GetAsync(s.App.Id));

        Assert.True(await r.Roles.DeleteAsync(s.Role.Id, 2));
        Assert.True(await r.Users.DeleteAsync(s.User.Id, 2));
        Assert.True(await r.Clients.DeleteAsync(s.Client.Id, 2));
        Assert.True(await r.Apps.DeleteAsync(s.App.Id, 2));
        Assert.False(await r.Apps.DeleteAsync(s.App.Id, 2));
    }

    [SkippableFact]
    public async Task Parallel_updates_with_the_same_expected_version_let_exactly_one_win()
    {
        var s = await Seed();
        var r = s.R;
        const int n = 8;
        async Task<int> Race(Func<int, Task> write)
        {
            var results = await Task.WhenAll(Enumerable.Range(0, n).Select(async i =>
            {
                try { await write(i); return true; }
                catch (PreconditionFailedException) { return false; }
            }));
            return results.Count(x => x);
        }
        Assert.Equal(1, await Race(i => r.Apps.UpdateAsync(s.App with { Name = $"shop-{i}" }, 1)));
        Assert.Equal(1, await Race(i => r.Roles.UpdateAsync(s.Role with { Description = $"d{i}" }, 1)));
        Assert.Equal(1, await Race(i => r.Users.UpdateAsync(s.User with { DisplayName = $"n{i}" }, 1)));
        Assert.Equal(1, await Race(i => r.Clients.UpdateAsync(s.Client with { Name = $"c-{i}" }, 1)));
        Assert.Equal(2, (await r.Apps.GetAsync(s.App.Id))!.Version);
        Assert.Equal(2, (await r.Roles.GetAsync(s.Role.Id))!.Version);
        Assert.Equal(2, (await r.Users.GetAsync(s.User.Id))!.Version);
        Assert.Equal(2, (await r.Clients.GetAsync(s.Client.Id))!.Version);

        // an update and a delete with the same expectation: one of them wins, never both
        var deleted = 0;
        var updated = 0;
        await Task.WhenAll(
            Task.Run(async () => { try { if (await r.Apps.UpdateAsync(s.App with { Name = "again" }, 2) is not null) Interlocked.Increment(ref updated); } catch (PreconditionFailedException) { } }),
            Task.Run(async () => { try { if (await r.Apps.DeleteAsync(s.App.Id, 2)) Interlocked.Increment(ref deleted); } catch (PreconditionFailedException) { } }));
        Assert.Equal(1, updated + deleted);
    }

    [SkippableFact]
    public async Task Parallel_unconditional_updates_all_succeed_and_each_adds_one()
    {
        var s = await Seed();
        var r = s.R;
        const int n = 8;
        await Task.WhenAll(Enumerable.Range(0, n).Select(i => r.Users.UpdateAsync(s.User with { DisplayName = $"n{i}" })));
        await Task.WhenAll(Enumerable.Range(0, n).Select(i => r.Clients.UpdateAsync(s.Client with { Name = $"c-{i}" })));
        Assert.Equal(1 + n, (await r.Users.GetAsync(s.User.Id))!.Version);
        Assert.Equal(1 + n, (await r.Clients.GetAsync(s.Client.Id))!.Version);
    }

    [SkippableFact]
    public async Task Role_assignments_passwords_and_secrets_do_not_change_a_version()
    {
        var s = await Seed();
        var r = s.R;
        await r.Users.AssignRoleAsync(s.User.Id, s.Role.Id);
        await r.Credentials.SetAsync(s.User.Id, "hash", T0);
        await r.Clients.AssignRoleAsync(s.Client.Id, s.Role.Id);
        await r.Clients.SetSecretHashAsync(s.Client.Id, "other", T0);
        await r.Users.RevokeRoleAsync(s.User.Id, s.Role.Id);
        Assert.Equal(1, (await r.Users.GetAsync(s.User.Id))!.Version);
        Assert.Equal(1, (await r.Clients.GetAsync(s.Client.Id))!.Version);
        Assert.Equal(1, (await r.Roles.GetAsync(s.Role.Id))!.Version);
        Assert.Equal(1, (await r.Apps.GetAsync(s.App.Id))!.Version);
    }
}

public class InMemorySlice6dStoreTests : Slice6dStoreTests
{
    protected override Repos Open()
    {
        var s = new InMemoryStore();
        return new Repos(new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s),
            new InMemoryClientRepository(s), new InMemoryCredentialRepository(s));
    }
}

public class PostgresSlice6dStoreTests : Slice6dStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];

    protected override Repos Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return new Repos(p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IRoleRepository>(), p.GetRequiredService<IUserRepository>(),
            p.GetRequiredService<IClientRepository>(), p.GetRequiredService<ICredentialRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }
}
