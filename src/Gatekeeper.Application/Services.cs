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
        await RejectReserved(id, "renamed", ct);
        return await apps.UpdateAsync(new App(id, name!), ct)
            ?? throw new NotFoundException($"Application {id} not found.");
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await RejectReserved(id, "deleted", ct);
        if (!await apps.DeleteAsync(id, ct)) throw new NotFoundException($"Application {id} not found.");
    }

    // Renaming or deleting the admin app would lock every administrator out.
    private async Task RejectReserved(Guid id, string action, CancellationToken ct)
    {
        if (await apps.GetAsync(id, ct) is { } app && string.Equals(app.Name, Reserved.AdminApp, StringComparison.OrdinalIgnoreCase))
            throw new ConflictException($"Application '{app.Name}' is reserved and cannot be {action}.");
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
        if (!string.Equals(existing.Name, name, StringComparison.OrdinalIgnoreCase)) await RejectReserved(existing, "renamed", ct);
        return await roles.UpdateAsync(existing with { Name = name!, Description = description ?? "" }, ct)
            ?? throw new NotFoundException($"Role {id} not found.");
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        if (await roles.GetAsync(id, ct) is { } existing) await RejectReserved(existing, "deleted", ct);
        if (!await roles.DeleteAsync(id, ct)) throw new NotFoundException($"Role {id} not found.");
    }

    private async Task RejectReserved(Role role, string action, CancellationToken ct)
    {
        if (!string.Equals(role.Name, Reserved.AdminRole, StringComparison.OrdinalIgnoreCase)) return;
        if (await apps.GetAsync(role.AppId, ct) is { } app && string.Equals(app.Name, Reserved.AdminApp, StringComparison.OrdinalIgnoreCase))
            throw new ConflictException($"Role '{role.Name}' of application '{app.Name}' is reserved and cannot be {action}.");
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

public sealed class CredentialService(IUserRepository users, ICredentialRepository credentials, IPasswordHasher hasher)
{
    public async Task SetPasswordAsync(Guid userId, string? password, CancellationToken ct = default)
    {
        Validation.Password(password);
        _ = await users.GetAsync(userId, ct) ?? throw new NotFoundException($"User {userId} not found.");
        // Argon2 is CPU and memory heavy; keep it off the request thread.
        var hash = await Task.Run(() => hasher.Hash(password!), ct);
        await credentials.SetAsync(userId, hash, Clock.UtcNowMicros(), ct);
    }
}

public sealed record AuthResult(User User, App App, IReadOnlyList<string> Roles);

/// <summary>
/// Verifies a user's password and resolves their roles in one application. Every failure returns null so callers
/// cannot tell an unknown user from a wrong password, an inactive account, an unknown application or no access.
/// A hash is verified on every attempt (against a dummy for unknown users) so timing does not reveal which case it was.
/// </summary>
public sealed class AuthService(
    IUserRepository users, IAppRepository apps, ICredentialRepository credentials, IPasswordHasher hasher)
{
    private readonly Lazy<string> _dummyHash = new(() => hasher.Hash(Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24))));

    public async Task<AuthResult?> LoginAsync(string? username, string? password, string? application, CancellationToken ct = default)
    {
        // Malformed input can never match; reject cheaply but still spend a hash so the response time stays similar.
        var wellFormed = username is { Length: > 0 and <= Validation.MaxNameLength } && Validation.IsCleanText(username)
                         && password is { Length: >= Validation.MinPasswordLength and <= Validation.MaxPasswordLength }
                         && application is { Length: > 0 and <= Validation.MaxNameLength } && Validation.IsCleanText(application);

        User? user = null;
        App? app = null;
        string? stored = null;
        if (wellFormed)
        {
            user = (await users.ListAsync(username: username, slice: new Slice(0, 1), ct: ct)).FirstOrDefault();
            app = await apps.GetByNameAsync(application!, ct);
            if (user is not null) stored = await credentials.GetHashAsync(user.Id, ct);
        }

        var hash = stored ?? _dummyHash.Value;
        var candidate = wellFormed ? password! : "dummy password for malformed input";
        var verified = await Task.Run(() => hasher.Verify(hash, candidate), ct);

        if (!wellFormed || user is null || stored is null || app is null || !verified || !user.IsActive) return null;

        var roles = await users.ListRolesAsync(user.Id, app.Id, new Slice(0, PageQuery.MaxLimit), ct);
        if (roles.Count == 0) return null;

        if (hasher.NeedsRehash(stored))
            await credentials.SetAsync(user.Id, await Task.Run(() => hasher.Hash(password!), ct), Clock.UtcNowMicros(), ct);

        return new AuthResult(user, app, roles.Select(r => r.Name).ToList());
    }
}
