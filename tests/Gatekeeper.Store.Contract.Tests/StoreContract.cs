using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Behaviour every store implementation must satisfy. Subclass per store.</summary>
public abstract class StoreContract
{
    protected abstract (IAppRepository Apps, IRoleRepository Roles, IUserRepository Users) CreateStore();

    private static User NewUser(string name, string? email = null) =>
        new(Guid.NewGuid(), name, email ?? $"{name}@example.com", name, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    private static App NewApp(string name) => new(Guid.NewGuid(), name);

    private static Role NewRole(App app, string name) => new(Guid.NewGuid(), app.Id, name, "");

    [Fact]
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

    [Fact]
    public async Task App_names_are_unique_case_insensitively()
    {
        var (apps, _, _) = CreateStore();
        await apps.AddAsync(NewApp("billing"));
        await Assert.ThrowsAsync<ConflictException>(() => apps.AddAsync(NewApp("BILLING")));
        var other = await apps.AddAsync(NewApp("crm"));
        await Assert.ThrowsAsync<ConflictException>(() => apps.UpdateAsync(other with { Name = "billing" }));
        await apps.UpdateAsync(other with { Name = "crm" }); // same name on itself is fine
    }

    [Fact]
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

    [Fact]
    public async Task User_username_and_email_are_unique()
    {
        var (_, _, users) = CreateStore();
        await users.AddAsync(NewUser("alice"));
        await Assert.ThrowsAsync<ConflictException>(() => users.AddAsync(NewUser("ALICE", "other@example.com")));
        await Assert.ThrowsAsync<ConflictException>(() => users.AddAsync(NewUser("bob", "Alice@Example.com")));
    }

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
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
        return (new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s));
    }
}
