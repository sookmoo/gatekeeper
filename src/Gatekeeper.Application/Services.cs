using Gatekeeper.Domain;

namespace Gatekeeper.Application;

public sealed class AppService(IAppRepository apps)
{
    public Task<IReadOnlyList<App>> ListAsync() => apps.ListAsync();

    public async Task<App> GetAsync(Guid id) =>
        await apps.GetAsync(id) ?? throw new NotFoundException($"Application {id} not found.");

    public Task<App> CreateAsync(string? name)
    {
        Validation.AppName(name);
        return apps.AddAsync(new App(Guid.NewGuid(), name!));
    }

    public async Task<App> UpdateAsync(Guid id, string? name)
    {
        Validation.AppName(name);
        return await apps.UpdateAsync(new App(id, name!))
            ?? throw new NotFoundException($"Application {id} not found.");
    }

    public async Task DeleteAsync(Guid id)
    {
        if (!await apps.DeleteAsync(id)) throw new NotFoundException($"Application {id} not found.");
    }
}

public sealed class RoleService(IAppRepository apps, IRoleRepository roles)
{
    public async Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId)
    {
        await RequireApp(appId);
        return await roles.ListByAppAsync(appId);
    }

    public async Task<Role> GetAsync(Guid id) =>
        await roles.GetAsync(id) ?? throw new NotFoundException($"Role {id} not found.");

    public async Task<Role> CreateAsync(Guid appId, string? name, string? description)
    {
        Validation.RoleFields(name, description);
        return await roles.AddAsync(new Role(Guid.NewGuid(), appId, name!, description ?? ""));
    }

    public async Task<Role> UpdateAsync(Guid id, string? name, string? description)
    {
        Validation.RoleFields(name, description);
        var existing = await GetAsync(id);
        return await roles.UpdateAsync(existing with { Name = name!, Description = description ?? "" })
            ?? throw new NotFoundException($"Role {id} not found.");
    }

    public async Task DeleteAsync(Guid id)
    {
        if (!await roles.DeleteAsync(id)) throw new NotFoundException($"Role {id} not found.");
    }

    private async Task RequireApp(Guid appId)
    {
        if (await apps.GetAsync(appId) is null) throw new NotFoundException($"Application {appId} not found.");
    }
}

public sealed class UserService(IUserRepository users)
{
    public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null) =>
        users.ListAsync(active, username);

    public async Task<User> GetAsync(Guid id) =>
        await users.GetAsync(id) ?? throw new NotFoundException($"User {id} not found.");

    public Task<User> CreateAsync(string? username, string? email, string? displayName, bool isActive = true)
    {
        Validation.UserFields(username, email, displayName);
        var now = DateTimeOffset.UtcNow;
        return users.AddAsync(new User(Guid.NewGuid(), username!, email!, displayName ?? "", isActive, now, now));
    }

    public async Task<User> UpdateAsync(Guid id, string? username, string? email, string? displayName, bool? isActive)
    {
        Validation.UserFields(username, email, displayName);
        var existing = await GetAsync(id);
        var updated = existing with
        {
            Username = username!,
            Email = email!,
            DisplayName = displayName ?? "",
            IsActive = isActive ?? existing.IsActive,
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        return await users.UpdateAsync(updated) ?? throw new NotFoundException($"User {id} not found.");
    }

    public async Task DeleteAsync(Guid id)
    {
        if (!await users.DeleteAsync(id)) throw new NotFoundException($"User {id} not found.");
    }

    public async Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null)
    {
        await GetAsync(userId);
        return await users.ListRolesAsync(userId, appId);
    }

    public async Task AssignRoleAsync(Guid userId, Guid roleId)
    {
        await users.AssignRoleAsync(userId, roleId); // store verifies user and role atomically
    }

    public async Task RevokeRoleAsync(Guid userId, Guid roleId)
    {
        await GetAsync(userId);
        // Revoking an assignment that does not exist is a 404 so callers notice typos.
        if (!await users.RevokeRoleAsync(userId, roleId))
            throw new NotFoundException($"User {userId} does not have role {roleId}.");
    }
}
