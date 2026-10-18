using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

public class ServiceTests
{
    private readonly AppService _apps;
    private readonly RoleService _roles;
    private readonly UserService _users;

    public ServiceTests()
    {
        var s = new InMemoryStore();
        var appRepo = new InMemoryAppRepository(s);
        var roleRepo = new InMemoryRoleRepository(s);
        var userRepo = new InMemoryUserRepository(s);
        _apps = new AppService(appRepo);
        _roles = new RoleService(appRepo, roleRepo);
        _users = new UserService(userRepo);
    }

    [Fact]
    public async Task Create_validates_before_storing()
    {
        await Assert.ThrowsAsync<ValidationException>(() => _apps.CreateAsync("Bad Name"));
        Assert.Empty((await _apps.ListAsync()).Items);
    }

    [Fact]
    public async Task Get_unknown_throws_NotFound()
    {
        await Assert.ThrowsAsync<NotFoundException>(() => _apps.GetAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<NotFoundException>(() => _users.GetAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<NotFoundException>(() => _roles.GetAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Role_requires_existing_app() =>
        await Assert.ThrowsAsync<NotFoundException>(() => _roles.CreateAsync(Guid.NewGuid(), "admin", null));

    [Fact]
    public async Task Roles_of_the_reserved_app_cannot_be_created_changed_or_deleted()
    {
        var s = new InMemoryStore();
        var appRepo = new InMemoryAppRepository(s);
        var roleRepo = new InMemoryRoleRepository(s);
        var roles = new RoleService(appRepo, roleRepo);
        var gk = await appRepo.AddAsync(new App(Guid.NewGuid(), Reserved.AdminApp));
        var admin = await roleRepo.AddAsync(new Role(Guid.NewGuid(), gk.Id, Reserved.AdminRole, "Manages Gatekeeper")); // seeding goes through the store
        await Assert.ThrowsAsync<ConflictException>(() => roles.CreateAsync(gk.Id, "extra", null));
        await Assert.ThrowsAsync<ConflictException>(() => roles.UpdateAsync(admin.Id, "admin", "tampered"));
        await Assert.ThrowsAsync<ConflictException>(() => roles.PatchAsync(admin.Id, null, "tampered"));
        await Assert.ThrowsAsync<ConflictException>(() => roles.DeleteAsync(admin.Id));
        Assert.Equal("Manages Gatekeeper", (await roles.GetAsync(admin.Id)).Description);
    }

    [Fact]
    public async Task Other_roles_of_the_reserved_app_can_be_deleted_but_not_assigned_and_checks_come_before_validation()
    {
        var s = new InMemoryStore();
        var appRepo = new InMemoryAppRepository(s);
        var roleRepo = new InMemoryRoleRepository(s);
        var userRepo = new InMemoryUserRepository(s);
        var roles = new RoleService(appRepo, roleRepo);
        var users = new UserService(userRepo, new AdminGuard(appRepo, roleRepo, userRepo));
        var gk = await appRepo.AddAsync(new App(Guid.NewGuid(), Reserved.AdminApp));
        var upper = await roleRepo.AddAsync(new Role(Guid.NewGuid(), gk.Id, "ADMIN", ""));
        var stray = await roleRepo.AddAsync(new Role(Guid.NewGuid(), gk.Id, "stray", ""));
        var user = await users.CreateAsync("alice", "alice@example.com", null);
        await Assert.ThrowsAsync<ConflictException>(() => users.AssignRoleAsync(user.Id, stray.Id));
        // invalid input to a reserved role is a 409, not a 400
        await Assert.ThrowsAsync<ConflictException>(() => roles.CreateAsync(gk.Id, "", null));
        await Assert.ThrowsAsync<ConflictException>(() => roles.UpdateAsync(stray.Id, "", null));
        await Assert.ThrowsAsync<ConflictException>(() => roles.UpdateAsync(stray.Id, "x", null));
        await Assert.ThrowsAsync<ConflictException>(() => roles.DeleteAsync(upper.Id)); // admin, ignoring case
        await roles.DeleteAsync(stray.Id);
        await Assert.ThrowsAsync<NotFoundException>(() => roles.GetAsync(stray.Id));
    }

    [Fact]
    public async Task Assign_requires_existing_user_and_role()
    {
        var app = await _apps.CreateAsync("a");
        var role = await _roles.CreateAsync(app.Id, "admin", null);
        var user = await _users.CreateAsync("alice", "alice@example.com", null);
        await Assert.ThrowsAsync<NotFoundException>(() => _users.AssignRoleAsync(Guid.NewGuid(), role.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => _users.AssignRoleAsync(user.Id, Guid.NewGuid()));
        await _users.AssignRoleAsync(user.Id, role.Id);
        Assert.Single((await _users.ListRolesAsync(user.Id)).Items);
    }

    [Fact]
    public async Task Revoke_of_unassigned_role_is_NotFound()
    {
        var app = await _apps.CreateAsync("a");
        var role = await _roles.CreateAsync(app.Id, "admin", null);
        var user = await _users.CreateAsync("alice", "alice@example.com", null);
        await Assert.ThrowsAsync<NotFoundException>(() => _users.RevokeRoleAsync(user.Id, role.Id));
    }

    [Fact]
    public async Task User_update_sets_UpdatedAt_and_keeps_CreatedAt()
    {
        var user = await _users.CreateAsync("alice", "alice@example.com", "Alice");
        var updated = await _users.UpdateAsync(user.Id, "alice", "alice@example.com", "Alice B", isActive: false);
        Assert.Equal(user.CreatedAt, updated.CreatedAt);
        Assert.True(updated.UpdatedAt >= user.UpdatedAt);
        Assert.False(updated.IsActive);
        Assert.Equal("Alice B", updated.DisplayName);
    }
}
