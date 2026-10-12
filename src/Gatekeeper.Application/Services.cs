using Gatekeeper.Domain;

namespace Gatekeeper.Application;

public sealed class AppService(IAppRepository apps)
{
    public async Task<Page<App>> ListAsync(PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        return page.Build(await apps.ListAsync(page.Slice, ct));
    }

    public async Task<App> GetAsync(Guid id, CancellationToken ct = default) =>
        await apps.GetAsync(id, ct) ?? throw new NotFoundException($"Application {id} not found.");

    public Task<App> CreateAsync(string? name, CancellationToken ct = default)
    {
        Validation.AppName(name);
        return apps.AddAsync(new App(Guid.NewGuid(), name!), ct);
    }

    public async Task<App> UpdateAsync(Guid id, string? name, CancellationToken ct = default)
    {
        Validation.AppName(name);
        return await apps.UpdateAsync(new App(id, name!), ct)
            ?? throw new NotFoundException($"Application {id} not found.");
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        if (!await apps.DeleteAsync(id, ct)) throw new NotFoundException($"Application {id} not found.");
    }
}

public sealed class RoleService(IAppRepository apps, IRoleRepository roles)
{
    public async Task<Page<Role>> ListByAppAsync(Guid appId, PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        await RequireApp(appId, ct);
        return page.Build(await roles.ListByAppAsync(appId, page.Slice, ct));
    }

    public async Task<Role> GetAsync(Guid id, CancellationToken ct = default) =>
        await roles.GetAsync(id, ct) ?? throw new NotFoundException($"Role {id} not found.");

    public async Task<Role> CreateAsync(Guid appId, string? name, string? description, CancellationToken ct = default)
    {
        Validation.RoleFields(name, description);
        return await roles.AddAsync(new Role(Guid.NewGuid(), appId, name!, description ?? ""), ct);
    }

    public async Task<Role> UpdateAsync(Guid id, string? name, string? description, CancellationToken ct = default)
    {
        Validation.RoleFields(name, description);
        var existing = await GetAsync(id, ct);
        return await roles.UpdateAsync(existing with { Name = name!, Description = description ?? "" }, ct)
            ?? throw new NotFoundException($"Role {id} not found.");
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        if (!await roles.DeleteAsync(id, ct)) throw new NotFoundException($"Role {id} not found.");
    }

    private async Task RequireApp(Guid appId, CancellationToken ct)
    {
        if (await apps.GetAsync(appId, ct) is null) throw new NotFoundException($"Application {appId} not found.");
    }
}

public sealed class UserService(IUserRepository users)
{
    public async Task<Page<User>> ListAsync(bool? active = null, string? username = null, PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        // No valid username contains control characters or malformed Unicode, so such a filter matches nothing.
        if (username is not null && !Validation.IsCleanText(username)) return page.Build<User>([]);
        return page.Build(await users.ListAsync(active, username, page.Slice, ct));
    }

    public async Task<User> GetAsync(Guid id, CancellationToken ct = default) =>
        await users.GetAsync(id, ct) ?? throw new NotFoundException($"User {id} not found.");

    public Task<User> CreateAsync(string? username, string? email, string? displayName, bool isActive = true, CancellationToken ct = default)
    {
        Validation.UserFields(username, email, displayName);
        var now = Clock.UtcNowMicros();
        return users.AddAsync(new User(Guid.NewGuid(), username!, email!, displayName ?? "", isActive, now, now), ct);
    }

    public async Task<User> UpdateAsync(Guid id, string? username, string? email, string? displayName, bool? isActive, CancellationToken ct = default)
    {
        Validation.UserFields(username, email, displayName);
        var existing = await GetAsync(id, ct);
        var updated = existing with
        {
            Username = username!,
            Email = email!,
            DisplayName = displayName ?? "",
            IsActive = isActive ?? existing.IsActive,
            UpdatedAt = Clock.UtcNowMicros(),
        };
        return await users.UpdateAsync(updated, ct) ?? throw new NotFoundException($"User {id} not found.");
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        if (!await users.DeleteAsync(id, ct)) throw new NotFoundException($"User {id} not found.");
    }

    public async Task<Page<Role>> ListRolesAsync(Guid userId, Guid? appId = null, PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        await GetAsync(userId, ct);
        return page.Build(await users.ListRolesAsync(userId, appId, page.Slice, ct));
    }

    public async Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        await users.AssignRoleAsync(userId, roleId, ct); // store verifies user and role atomically
    }

    public async Task RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        await GetAsync(userId, ct);
        // Revoking an assignment that does not exist is a 404 so callers notice typos.
        if (!await users.RevokeRoleAsync(userId, roleId, ct))
            throw new NotFoundException($"User {userId} does not have role {roleId}.");
    }
}
