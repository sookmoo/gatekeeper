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
        Assert.Empty(await _apps.ListAsync());
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
    public async Task Assign_requires_existing_user_and_role()
    {
        var app = await _apps.CreateAsync("a");
        var role = await _roles.CreateAsync(app.Id, "admin", null);
        var user = await _users.CreateAsync("alice", "alice@example.com", null);
        await Assert.ThrowsAsync<NotFoundException>(() => _users.AssignRoleAsync(Guid.NewGuid(), role.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => _users.AssignRoleAsync(user.Id, Guid.NewGuid()));
        await _users.AssignRoleAsync(user.Id, role.Id);
        Assert.Single(await _users.ListRolesAsync(user.Id));
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
