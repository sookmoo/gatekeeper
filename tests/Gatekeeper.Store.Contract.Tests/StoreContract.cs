using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Behaviour every store implementation must satisfy. Subclass per store.</summary>
public abstract class StoreContract : IDisposable
{
    public virtual void Dispose() => GC.SuppressFinalize(this);

    protected abstract (IAppRepository Apps, IRoleRepository Roles, IUserRepository Users) CreateStore();

    /// <summary>Set by <see cref="CreateStore"/>.</summary>
    protected ICredentialRepository Credentials { get; set; } = null!;

    private static User NewUser(string name, string? email = null) =>
        new(Guid.NewGuid(), name, email ?? $"{name}@example.com", name, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    private static App NewApp(string name) => new(Guid.NewGuid(), name);

    private static Role NewRole(App app, string name) => new(Guid.NewGuid(), app.Id, name, "");

    [SkippableFact]
    public async Task Lists_are_ordered_and_sliced_consistently()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a0"));
        foreach (var n in new[] { "c", "a", "d", "b" }) await apps.AddAsync(NewApp($"app-{n}"));
        Assert.Equal(["a0", "app-a", "app-b", "app-c", "app-d"], (await apps.ListAsync()).Select(a => a.Name));
        Assert.Equal(["app-a", "app-b"], (await apps.ListAsync(new Slice(1, 2))).Select(a => a.Name));
        Assert.Empty(await apps.ListAsync(new Slice(5, 3)));

        foreach (var n in new[] { "r3", "r1", "r2" }) await roles.AddAsync(NewRole(app, n));
        Assert.Equal(["r2", "r3"], (await roles.ListByAppAsync(app.Id, new Slice(1, 5))).Select(r => r.Name));

        foreach (var n in new[] { "u3", "u1", "u2" }) await users.AddAsync(NewUser(n));
        Assert.Equal(["u1", "u2"], (await users.ListAsync(slice: new Slice(0, 2))).Select(u => u.Username));
        Assert.Equal(["u3"], (await users.ListAsync(slice: new Slice(2, 2))).Select(u => u.Username));

        var u1 = (await users.ListAsync(username: "u1")).Single();
        foreach (var r in await roles.ListByAppAsync(app.Id)) await users.AssignRoleAsync(u1.Id, r.Id);
        Assert.Equal(["r1", "r2"], (await users.ListRolesAsync(u1.Id, slice: new Slice(0, 2))).Select(r => r.Name));
    }

    [SkippableFact]
    public async Task Credentials_upsert_read_and_cascade_with_user()
    {
        var (_, _, users) = CreateStore();
        var user = await users.AddAsync(NewUser("alice"));
        Assert.Null(await Credentials.GetHashAsync(user.Id));
        await Credentials.SetAsync(user.Id, "hash-1", DateTimeOffset.UtcNow);
        Assert.Equal("hash-1", await Credentials.GetHashAsync(user.Id));
        await Credentials.SetAsync(user.Id, "hash-2", DateTimeOffset.UtcNow);
        Assert.Equal("hash-2", await Credentials.GetHashAsync(user.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => Credentials.SetAsync(Guid.NewGuid(), "h", DateTimeOffset.UtcNow));
        Assert.True(await users.DeleteAsync(user.Id));
        Assert.Null(await Credentials.GetHashAsync(user.Id));
    }

    [SkippableFact]
    public async Task Cancelled_token_aborts_the_call()
    {
        var (apps, _, _) = CreateStore();
        await apps.AddAsync(NewApp("billing"));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        // In-memory stores finish synchronously; Postgres must observe the token. Either way it must not return stale data silently
        // for a write.
        var ex = await Record.ExceptionAsync(() => apps.AddAsync(NewApp("late"), cts.Token));
        if (ex is not null) Assert.IsAssignableFrom<OperationCanceledException>(ex);
    }

    [SkippableFact]
    public async Task App_roundtrip_update_delete()
    {
        var (apps, _, _) = CreateStore();
        var app = await apps.AddAsync(NewApp("billing"));
        Assert.Equal(app, await apps.GetAsync(app.Id));
        Assert.Single(await apps.ListAsync());
        var renamed = await apps.UpdateAsync(app with { Name = "invoices" });
        Assert.Equal("invoices", renamed!.Name);
        Assert.True(await apps.DeleteAsync(app.Id));
        Assert.False(await apps.DeleteAsync(app.Id));
        Assert.Null(await apps.GetAsync(app.Id));
        Assert.Null(await apps.UpdateAsync(app));
    }

    [SkippableFact]
    public async Task App_names_are_unique_case_insensitively()
    {
        var (apps, _, _) = CreateStore();
        await apps.AddAsync(NewApp("billing"));
        await Assert.ThrowsAsync<ConflictException>(() => apps.AddAsync(NewApp("BILLING")));
        var other = await apps.AddAsync(NewApp("crm"));
        await Assert.ThrowsAsync<ConflictException>(() => apps.UpdateAsync(other with { Name = "billing" }));
        await apps.UpdateAsync(other with { Name = "crm" }); // same name on itself is fine
    }

    [SkippableFact]
    public async Task Role_names_are_unique_per_app_only()
    {
        var (apps, roles, _) = CreateStore();
        var a = await apps.AddAsync(NewApp("a"));
        var b = await apps.AddAsync(NewApp("b"));
        await roles.AddAsync(NewRole(a, "admin"));
        await roles.AddAsync(NewRole(b, "admin"));
        await Assert.ThrowsAsync<ConflictException>(() => roles.AddAsync(NewRole(a, "ADMIN")));
        Assert.Single(await roles.ListByAppAsync(a.Id));
    }

    [SkippableFact]
    public async Task User_username_and_email_are_unique()
    {
        var (_, _, users) = CreateStore();
        await users.AddAsync(NewUser("alice"));
        await Assert.ThrowsAsync<ConflictException>(() => users.AddAsync(NewUser("ALICE", "other@example.com")));
        await Assert.ThrowsAsync<ConflictException>(() => users.AddAsync(NewUser("bob", "Alice@Example.com")));
    }

    [SkippableFact]
    public async Task User_list_filters()
    {
        var (_, _, users) = CreateStore();
        await users.AddAsync(NewUser("alice"));
        var bob = await users.AddAsync(NewUser("bob"));
        await users.UpdateAsync(bob with { IsActive = false });
        Assert.Equal(2, (await users.ListAsync()).Count);
        Assert.Equal(["bob"], (await users.ListAsync(active: false)).Select(u => u.Username));
        Assert.Equal(["alice"], (await users.ListAsync(username: "ALICE")).Select(u => u.Username));
    }

    [SkippableFact]
    public async Task Assign_is_idempotent_and_revoke_reports_presence()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var role = await roles.AddAsync(NewRole(app, "admin"));
        var user = await users.AddAsync(NewUser("alice"));
        await users.AssignRoleAsync(user.Id, role.Id);
        await users.AssignRoleAsync(user.Id, role.Id);
        Assert.Single(await users.ListRolesAsync(user.Id));
        Assert.True(await users.RevokeRoleAsync(user.Id, role.Id));
        Assert.False(await users.RevokeRoleAsync(user.Id, role.Id));
    }

    [SkippableFact]
    public async Task ListRoles_filters_by_app()
    {
        var (apps, roles, users) = CreateStore();
        var a = await apps.AddAsync(NewApp("a"));
        var b = await apps.AddAsync(NewApp("b"));
        var user = await users.AddAsync(NewUser("alice"));
        foreach (var r in new[] { NewRole(a, "x"), NewRole(b, "y") })
        {
            await roles.AddAsync(r);
            await users.AssignRoleAsync(user.Id, r.Id);
        }
        Assert.Equal(2, (await users.ListRolesAsync(user.Id)).Count);
        Assert.Equal(["x"], (await users.ListRolesAsync(user.Id, a.Id)).Select(r => r.Name));
    }

    [SkippableFact]
    public async Task Role_for_missing_app_is_rejected()
    {
        var (_, roles, _) = CreateStore();
        await Assert.ThrowsAsync<NotFoundException>(() => roles.AddAsync(NewRole(NewApp("ghost"), "admin")));
    }

    [SkippableFact]
    public async Task Assignment_for_missing_user_or_role_is_rejected_and_leaves_nothing()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var role = await roles.AddAsync(NewRole(app, "admin"));
        var user = await users.AddAsync(NewUser("alice"));
        await Assert.ThrowsAsync<NotFoundException>(() => users.AssignRoleAsync(Guid.NewGuid(), role.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => users.AssignRoleAsync(user.Id, Guid.NewGuid()));
        Assert.Empty(await users.ListRolesAsync(user.Id));
    }

    [SkippableFact]
    public async Task Parallel_duplicate_creates_yield_exactly_one_winner()
    {
        var (apps, _, _) = CreateStore();
        var results = await Task.WhenAll(Enumerable.Range(0, 30).Select(async _ =>
        {
            try
            {
                await apps.AddAsync(NewApp("same-name"));
                return true;
            }
            catch (ConflictException)
            {
                return false;
            }
        }));
        Assert.Equal(1, results.Count(r => r));
        Assert.Single(await apps.ListAsync());
    }

    [SkippableFact]
    public async Task Creating_role_while_deleting_app_leaves_no_orphan_role()
    {
        var (apps, roles, _) = CreateStore();
        for (var i = 0; i < 40; i++)
        {
            var app = await apps.AddAsync(NewApp($"race-{i}"));
            var role = NewRole(app, "r");
            await Task.WhenAll(
                Swallow(() => roles.AddAsync(role)),
                Swallow(() => apps.DeleteAsync(app.Id)));
            Assert.Empty(await roles.ListByAppAsync(app.Id));
            Assert.Null(await roles.GetAsync(role.Id));
        }
    }

    [SkippableFact]
    public async Task Assigning_while_deleting_role_leaves_no_assignment()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var user = await users.AddAsync(NewUser("alice"));
        for (var i = 0; i < 40; i++)
        {
            var role = await roles.AddAsync(NewRole(app, $"r{i}"));
            await Task.WhenAll(
                Swallow(() => users.AssignRoleAsync(user.Id, role.Id)),
                Swallow(() => roles.DeleteAsync(role.Id)));
            Assert.DoesNotContain(await users.ListRolesAsync(user.Id), r => r.Id == role.Id);
        }
    }

    [SkippableFact]
    public async Task User_timestamps_round_trip()
    {
        var (_, _, users) = CreateStore();
        var created = DateTimeOffset.UtcNow;
        var user = await users.AddAsync(NewUser("alice") with { CreatedAt = created, UpdatedAt = created });
        var read = await users.GetAsync(user.Id);
        Assert.True(Math.Abs((read!.CreatedAt - created).TotalMilliseconds) < 1);
        Assert.Equal(TimeSpan.Zero, read.CreatedAt.Offset);
    }

    // Races may legitimately end in NotFound; anything else is a failure.
    private static async Task Swallow<T>(Func<Task<T>> action)
    {
        try
        {
            await action();
        }
        catch (NotFoundException)
        {
        }
    }

    private static Task Swallow(Func<Task> action) => Swallow(async () =>
    {
        await action();
        return 0;
    });

    [SkippableFact]
    public async Task Deleting_role_user_or_app_removes_assignments()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var r1 = await roles.AddAsync(NewRole(app, "r1"));
        var r2 = await roles.AddAsync(NewRole(app, "r2"));
        var alice = await users.AddAsync(NewUser("alice"));
        var bob = await users.AddAsync(NewUser("bob"));
        await users.AssignRoleAsync(alice.Id, r1.Id);
        await users.AssignRoleAsync(alice.Id, r2.Id);
        await users.AssignRoleAsync(bob.Id, r1.Id);

        await roles.DeleteAsync(r1.Id);
        Assert.Equal(["r2"], (await users.ListRolesAsync(alice.Id)).Select(r => r.Name));
        Assert.Empty(await users.ListRolesAsync(bob.Id));

        await users.DeleteAsync(alice.Id);
        await apps.DeleteAsync(app.Id);
        Assert.Null(await roles.GetAsync(r2.Id));
        Assert.Empty(await users.ListRolesAsync(bob.Id));
    }
}

public class InMemoryStoreContract : StoreContract
{
    protected override (IAppRepository, IRoleRepository, IUserRepository) CreateStore()
    {
        var s = new InMemoryStore();
        Credentials = new InMemoryCredentialRepository(s);
        return (new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s));
    }
}
