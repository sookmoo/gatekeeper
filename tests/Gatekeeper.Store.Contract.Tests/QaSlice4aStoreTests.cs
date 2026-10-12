using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>QA slice 4a: cancellation, paging edge cases and credential contract, run against both stores.</summary>
public abstract class QaSlice4aStoreTests : IDisposable
{
    protected abstract bool HonoursCancellation { get; }
    protected abstract (IAppRepository A, IRoleRepository R, IUserRepository U, ICredentialRepository C) Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static User U(string n, string? email = null, bool active = true) =>
        new(Guid.NewGuid(), n, email ?? $"{n}@example.com", n, active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    [SkippableFact]
    public async Task Every_port_method_observes_a_cancelled_token_without_applying_writes()
    {
        var (apps, roles, users, creds) = Open();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var role = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "r1", ""));
        var user = await users.AddAsync(U("u1"));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var ct = cts.Token;

        var calls = new (string, Func<Task>)[]
        {
            ("apps.List", () => apps.ListAsync(null, ct)), ("apps.Get", () => apps.GetAsync(app.Id, ct)), ("apps.GetByName", () => apps.GetByNameAsync("a1", ct)),
            ("apps.Add", () => apps.AddAsync(new App(Guid.NewGuid(), "late-app"), ct)), ("apps.Update", () => apps.UpdateAsync(app with { Name = "renamed" }, ct)),
            ("apps.Delete", () => apps.DeleteAsync(app.Id, ct)),
            ("roles.ListByApp", () => roles.ListByAppAsync(app.Id, null, ct)), ("roles.Get", () => roles.GetAsync(role.Id, ct)),
            ("roles.Add", () => roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "late-role", ""), ct)), ("roles.Update", () => roles.UpdateAsync(role with { Name = "renamed" }, ct)),
            ("roles.Delete", () => roles.DeleteAsync(role.Id, ct)),
            ("users.List", () => users.ListAsync(null, null, null, ct)), ("users.Get", () => users.GetAsync(user.Id, ct)),
            ("users.Add", () => users.AddAsync(U("late-user"), ct)), ("users.Update", () => users.UpdateAsync(user with { DisplayName = "x" }, ct)),
            ("users.Delete", () => users.DeleteAsync(user.Id, ct)), ("users.Assign", () => users.AssignRoleAsync(user.Id, role.Id, ct)),
            ("users.Revoke", () => users.RevokeRoleAsync(user.Id, role.Id, ct)), ("users.ListRoles", () => users.ListRolesAsync(user.Id, null, null, ct)),
            ("creds.Set", () => creds.SetAsync(user.Id, "h", DateTimeOffset.UtcNow, ct)), ("creds.Get", () => creds.GetHashAsync(user.Id, ct)),
        };
        var ignored = new List<string>();
        foreach (var (name, call) in calls)
        {
            // A store that ignores tokens would really delete; those calls are only meaningful where cancellation is honoured.
            if (!HonoursCancellation && (name.EndsWith(".Delete") || name.EndsWith(".Add") || name.EndsWith(".Update") || name.EndsWith(".Set"))) continue;
            var ex = await Record.ExceptionAsync(call);
            if (ex is null) ignored.Add(name);
            else Assert.True(ex is OperationCanceledException, $"{name} threw {ex.GetType().Name}: {ex.Message}");
        }
        if (HonoursCancellation) Assert.True(ignored.Count == 0, "ignored a cancelled token: " + string.Join(", ", ignored));

        // A cancelled write must not have changed anything that was refused.
        if (HonoursCancellation)
        {
            Assert.Null(await apps.GetByNameAsync("late-app"));
            Assert.Equal("a1", (await apps.GetAsync(app.Id))!.Name);
            Assert.Equal("r1", (await roles.GetAsync(role.Id))!.Name);
            Assert.Empty(await users.ListAsync(username: "late-user"));
            Assert.Null(await creds.GetHashAsync(user.Id));
            Assert.Empty(await users.ListRolesAsync(user.Id));
        }
    }

    [SkippableFact]
    public async Task Slices_at_boundaries()
    {
        var (apps, _, users, _) = Open();
        for (var i = 0; i < 5; i++) await apps.AddAsync(new App(Guid.NewGuid(), $"a{i}"));
        Assert.Equal(5, (await apps.ListAsync(new Slice(0, 5))).Count);
        Assert.Equal(5, (await apps.ListAsync(new Slice(0, 6))).Count);
        Assert.Equal(["a4"], (await apps.ListAsync(new Slice(4, 3))).Select(a => a.Name));
        Assert.Empty(await apps.ListAsync(new Slice(5, 1)));
        Assert.Empty(await apps.ListAsync(new Slice(1_000_000, 201)));
        Assert.Equal(5, (await apps.ListAsync(null)).Count);
        Assert.Empty(await users.ListAsync(slice: new Slice(0, 201)));
        // stable across repeated reads
        Assert.Equal((await apps.ListAsync(new Slice(1, 2))).Select(a => a.Id), (await apps.ListAsync(new Slice(1, 2))).Select(a => a.Id));
    }

    [SkippableFact]
    public async Task Ordering_is_ordinal_and_identical_in_both_stores()
    {
        var (apps, roles, users, _) = Open();
        var names = new[] { "a", "a-b", "a.b", "a_b", "a1", "ab", "b", "0a", "9", "a--b", "a-", "az", "a0", "a-0", "a.", "a_" };
        foreach (var n in names) await apps.AddAsync(new App(Guid.NewGuid(), n));
        var app = (await apps.ListAsync()).First();
        foreach (var n in names) await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, n, ""));
        foreach (var n in names) await users.AddAsync(U(n));
        var expected = names.Order(StringComparer.Ordinal).ToList();
        Assert.Equal(expected, (await apps.ListAsync()).Select(a => a.Name));
        Assert.Equal(expected, (await roles.ListByAppAsync(app.Id)).Select(r => r.Name));
        Assert.Equal(expected, (await users.ListAsync()).Select(x => x.Username));
        // user roles come out in the same order as role names
        var u = (await users.ListAsync()).First();
        foreach (var r in await roles.ListByAppAsync(app.Id)) await users.AssignRoleAsync(u.Id, r.Id);
        Assert.Equal(expected, (await users.ListRolesAsync(u.Id)).Select(r => r.Name));
    }

    [SkippableFact]
    public async Task Filtered_slices_page_correctly_and_username_filter_is_case_insensitive_exact()
    {
        var (_, _, users, _) = Open();
        for (var i = 0; i < 7; i++) await users.AddAsync(U($"p{i}", active: i % 2 == 0));
        Assert.Equal(["p0", "p2", "p4"], (await users.ListAsync(true, null, new Slice(0, 3))).Select(x => x.Username));
        Assert.Equal(["p6"], (await users.ListAsync(true, null, new Slice(3, 3))).Select(x => x.Username));
        Assert.Equal(["p1", "p3"], (await users.ListAsync(false, null, new Slice(0, 2))).Select(x => x.Username));
        Assert.Single(await users.ListAsync(username: "P3"));
        Assert.Empty(await users.ListAsync(username: "p"));      // exact, not prefix
        Assert.Empty(await users.ListAsync(username: "p%"));     // LIKE metacharacters are literals
        Assert.Empty(await users.ListAsync(username: "p_"));
        Assert.Empty(await users.ListAsync(username: "%"));
        Assert.Empty(await users.ListAsync(username: ""));
        Assert.Empty(await users.ListAsync(true, "p1"));
    }

    [SkippableFact]
    public async Task Credentials_survive_user_updates_and_never_cross_users_even_for_recreated_names()
    {
        var (_, _, users, creds) = Open();
        var a = await users.AddAsync(U("alice"));
        var b = await users.AddAsync(U("bob"));
        await creds.SetAsync(a.Id, "hash-a", DateTimeOffset.UtcNow);
        await creds.SetAsync(b.Id, "hash-b", DateTimeOffset.UtcNow);
        await users.UpdateAsync(a with { Username = "alice2" });
        Assert.Equal("hash-a", await creds.GetHashAsync(a.Id));
        Assert.Equal("hash-b", await creds.GetHashAsync(b.Id));
        await users.DeleteAsync(a.Id);
        var again = await users.AddAsync(U("alice"));
        Assert.Null(await creds.GetHashAsync(again.Id));
        Assert.Null(await creds.GetHashAsync(a.Id));
        Assert.Null(await creds.GetHashAsync(Guid.NewGuid()));
        // upsert is idempotent and last write wins; very long hash text is stored verbatim
        var big = new string('x', 500);
        await creds.SetAsync(b.Id, big, DateTimeOffset.UtcNow);
        Assert.Equal(big, await creds.GetHashAsync(b.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => creds.SetAsync(a.Id, "h", DateTimeOffset.UtcNow));
    }

    [SkippableFact]
    public async Task Concurrent_credential_upserts_do_not_fail()
    {
        var (_, _, users, creds) = Open();
        var u = await users.AddAsync(U("racer"));
        await Task.WhenAll(Enumerable.Range(0, 20).Select(i => creds.SetAsync(u.Id, $"hash-{i}", DateTimeOffset.UtcNow)));
        Assert.StartsWith("hash-", await creds.GetHashAsync(u.Id));
    }

    [SkippableFact]
    public async Task Concurrent_assignments_are_idempotent()
    {
        var (apps, roles, users, _) = Open();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "ca"));
        var role = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "cr", ""));
        var u = await users.AddAsync(U("assign1"));
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => users.AssignRoleAsync(u.Id, role.Id)));
        Assert.Single(await users.ListRolesAsync(u.Id));
    }

    [SkippableFact]
    public async Task Deleting_a_role_or_app_removes_it_from_the_users_role_list_and_pages_stay_consistent()
    {
        var (apps, roles, users, _) = Open();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "da"));
        var u = await users.AddAsync(U("del1"));
        var rs = new List<Role>();
        for (var i = 0; i < 5; i++) { var r = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, $"r{i}", "")); rs.Add(r); await users.AssignRoleAsync(u.Id, r.Id); }
        await roles.DeleteAsync(rs[2].Id);
        Assert.Equal(["r0", "r1", "r3", "r4"], (await users.ListRolesAsync(u.Id, app.Id, new Slice(0, 10))).Select(r => r.Name));
        Assert.Equal(["r3", "r4"], (await users.ListRolesAsync(u.Id, app.Id, new Slice(2, 10))).Select(r => r.Name));
        await apps.DeleteAsync(app.Id);
        Assert.Empty(await users.ListRolesAsync(u.Id));
    }
}

public class InMemoryQaSlice4aStoreTests : QaSlice4aStoreTests
{
    protected override bool HonoursCancellation => false; // README/Repositories: "honoured where the store supports it"
    protected override (IAppRepository, IRoleRepository, IUserRepository, ICredentialRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s), new InMemoryCredentialRepository(s));
    }
}

public class PostgresQaSlice4aStoreTests : QaSlice4aStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];
    protected override bool HonoursCancellation => true;

    protected override (IAppRepository, IRoleRepository, IUserRepository, ICredentialRepository) Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IRoleRepository>(), p.GetRequiredService<IUserRepository>(), p.GetRequiredService<ICredentialRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }
}
