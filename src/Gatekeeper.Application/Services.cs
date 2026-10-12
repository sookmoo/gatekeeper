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
        RejectReservedName(name!);
        return apps.AddAsync(new App(Guid.NewGuid(), name!), ct);
    }

    public async Task<App> UpdateAsync(Guid id, string? name, CancellationToken ct = default)
    {
        Validation.AppName(name);
        await RejectReserved(id, "renamed", ct);
        RejectReservedName(name!);
        return await apps.UpdateAsync(new App(id, name!), ct)
            ?? throw new NotFoundException($"Application {id} not found.");
    }

    /// <summary>Partial update: a null field is left unchanged.</summary>
    public async Task<App> PatchAsync(Guid id, string? name, CancellationToken ct = default) =>
        await UpdateAsync(id, name ?? (await GetAsync(id, ct)).Name, ct);

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await RejectReserved(id, "deleted", ct);
        if (!await apps.DeleteAsync(id, ct)) throw new NotFoundException($"Application {id} not found.");
    }

    // Only bootstrap-admin creates the admin app; letting anyone claim the name would hand them the admin audience.
    private static void RejectReservedName(string name)
    {
        if (string.Equals(name, Reserved.AdminApp, StringComparison.OrdinalIgnoreCase))
            throw new ConflictException($"Application name '{name}' is reserved.");
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

    /// <summary>Partial update: a null field is left unchanged (use an empty description to clear it).</summary>
    public async Task<Role> PatchAsync(Guid id, string? name, string? description, CancellationToken ct = default)
    {
        var existing = await GetAsync(id, ct);
        return await UpdateAsync(id, name ?? existing.Name, description ?? existing.Description, ct);
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

public sealed class UserService(IUserRepository users, AdminGuard? guard = null)
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
        if (isActive == false && existing.IsActive && guard is not null)
            return await guard.ExclusiveAsync(async () =>
            {
                await guard.EnsureNotLastAdminAsync(id, ct);
                return await Save(existing, username, email, displayName, isActive, ct);
            }, ct);
        return await Save(existing, username, email, displayName, isActive, ct);
    }

    /// <summary>Partial update: a null field is left unchanged (use an empty display name to clear it).</summary>
    public async Task<User> PatchAsync(Guid id, string? username, string? email, string? displayName, bool? isActive, CancellationToken ct = default)
    {
        var e = await GetAsync(id, ct);
        return await UpdateAsync(id, username ?? e.Username, email ?? e.Email, displayName ?? e.DisplayName, isActive, ct);
    }

    private async Task<User> Save(User existing, string? username, string? email, string? displayName, bool? isActive, CancellationToken ct)
    {
        var id = existing.Id;
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
        if (guard is null) { await Delete(id, ct); return; }
        await guard.ExclusiveAsync(async () =>
        {
            await guard.EnsureNotLastAdminAsync(id, ct);
            await Delete(id, ct);
            return 0;
        }, ct);
    }

    private async Task Delete(Guid id, CancellationToken ct)
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
        if (guard is null) { await Revoke(userId, roleId, ct); return; }
        await guard.ExclusiveAsync(async () =>
        {
            if (await guard.AdminRoleIdAsync(ct) == roleId) await guard.EnsureNotLastAdminAsync(userId, ct);
            await Revoke(userId, roleId, ct);
            return 0;
        }, ct);
    }

    private async Task Revoke(Guid userId, Guid roleId, CancellationToken ct)
    {
        // Revoking an assignment that does not exist is a 404 so callers notice typos.
        if (!await users.RevokeRoleAsync(userId, roleId, ct))
            throw new NotFoundException($"User {userId} does not have role {roleId}.");
    }
}

/// <summary>
/// Keeps at least one active administrator. Admin-affecting changes (delete, deactivate, revoke the admin role)
/// run one at a time in this process and are refused if they would leave nobody able to manage Gatekeeper.
/// </summary>
public sealed class AdminGuard(IAppRepository apps, IRoleRepository roles, IUserRepository users)
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<T> ExclusiveAsync<T>(Func<Task<T>> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            return await action();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<Guid?> AdminRoleIdAsync(CancellationToken ct)
    {
        var app = await apps.GetByNameAsync(Reserved.AdminApp, ct);
        if (app is null) return null;
        var role = (await roles.ListByAppAsync(app.Id, ct: ct)).FirstOrDefault(r =>
            string.Equals(r.Name, Reserved.AdminRole, StringComparison.OrdinalIgnoreCase));
        return role?.Id;
    }

    /// <summary>Throws Conflict if the user is an active administrator and nobody else active holds the admin role.</summary>
    public async Task EnsureNotLastAdminAsync(Guid userId, CancellationToken ct)
    {
        if (await AdminRoleIdAsync(ct) is not { } adminRole) return;
        var held = (await users.ListRolesAsync(userId, slice: new Slice(0, 10_000), ct: ct)).Any(r => r.Id == adminRole);
        if (!held || await users.GetAsync(userId, ct) is not { IsActive: true }) return;
        if (await users.CountActiveWithRoleAsync(adminRole, userId, ct) == 0)
            throw new ConflictException("This would leave Gatekeeper without an active administrator.");
    }
}

public sealed class CredentialService(IUserRepository users, ICredentialRepository credentials, IPasswordHasher hasher, HashLimiter? limiter = null)
{
    private readonly HashLimiter _limiter = limiter ?? new HashLimiter();

    public async Task SetPasswordAsync(Guid userId, string? password, CancellationToken ct = default)
    {
        Validation.Password(password);
        _ = await users.GetAsync(userId, ct) ?? throw new NotFoundException($"User {userId} not found.");
        // Argon2 is CPU and memory heavy: bounded parallelism, off the request thread.
        var hash = await _limiter.RunAsync(() => hasher.Hash(password!), ct);
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
    IUserRepository users, IAppRepository apps, ICredentialRepository credentials, IPasswordHasher hasher, HashLimiter? limiter = null)
{
    private readonly HashLimiter _limiter = limiter ?? new HashLimiter();
    private readonly Lazy<string> _dummyHash = new(() => hasher.Hash(Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24))));

    public async Task<AuthResult?> LoginAsync(string? username, string? password, string? application, CancellationToken ct = default)
    {
        // Malformed input can never match; reject cheaply but still spend a hash so the response time stays similar.
        var wellFormed = Validation.LooksLikeUsername(username) && Validation.IsCleanText(username!)
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

        var hash = stored ?? await _limiter.RunAsync(() => _dummyHash.Value, ct);
        var candidate = wellFormed ? password! : "dummy password for malformed input";
        var verified = await _limiter.RunAsync(() => hasher.Verify(hash, candidate), ct);

        if (!wellFormed || user is null || stored is null || app is null || !verified || !user.IsActive) return null;

        // All of the user's roles in this application: a silent cut-off would make consumers deny legitimate access.
        var names = new List<string>();
        const int pageSize = PageQuery.MaxLimit;
        while (true)
        {
            var batch = await users.ListRolesAsync(user.Id, app.Id, new Slice(names.Count, pageSize), ct);
            names.AddRange(batch.Select(r => r.Name));
            if (batch.Count < pageSize) break;
        }
        if (names.Count == 0) return null;

        if (hasher.NeedsRehash(stored))
        {
            // Compare-and-set: if the password was changed meanwhile, the newer hash must win.
            var upgraded = await _limiter.RunAsync(() => hasher.Hash(password!), ct);
            await credentials.ReplaceHashAsync(user.Id, stored, upgraded, Clock.UtcNowMicros(), ct);
        }

        return new AuthResult(user, app, names);
    }
}
