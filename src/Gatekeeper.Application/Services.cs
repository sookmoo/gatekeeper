using Gatekeeper.Domain;

namespace Gatekeeper.Application;

/// <summary>
/// PATCH reads, merges and writes back, so two at once could overwrite each other's fields (a lost "disable" is a security
/// problem). They run one at a time in this process, like <see cref="AdminGuard"/>; a multi-instance setup needs
/// repository-level partial updates instead.
/// </summary>
internal static class PatchGate
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static async Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken ct)
    {
        await Gate.WaitAsync(ct);
        try
        {
            return await action();
        }
        finally
        {
            Gate.Release();
        }
    }
}

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
    public Task<App> PatchAsync(Guid id, string? name, CancellationToken ct = default) => PatchGate.RunAsync(async () =>
    {
        var existing = await GetAsync(id, ct);
        return name is null || string.Equals(name, existing.Name, StringComparison.Ordinal) ? existing : await UpdateAsync(id, name, ct);
    }, ct);

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
    public Task<Role> PatchAsync(Guid id, string? name, string? description, CancellationToken ct = default) => PatchGate.RunAsync(async () =>
    {
        var existing = await GetAsync(id, ct);
        return await UpdateAsync(id, name ?? existing.Name, description ?? existing.Description, ct);
    }, ct);

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
    public Task<User> PatchAsync(Guid id, string? username, string? email, string? displayName, bool? isActive, CancellationToken ct = default) => PatchGate.RunAsync(async () =>
    {
        var e = await GetAsync(id, ct);
        return await UpdateAsync(id, username ?? e.Username, email ?? e.Email, displayName ?? e.DisplayName, isActive, ct);
    }, ct);

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

/// <summary>
/// Writes and reads the audit trail. Text is cut to a fixed length and stripped of control, format and unpaired
/// surrogate characters so an attacker-chosen value (for example a login name) cannot forge lines or flood a row.
/// </summary>
public sealed class AuditService(IAuditRepository audit)
{
    public Task RecordAsync(string actor, string action, string? target, bool success, string? detail = null, string? address = null, CancellationToken ct = default) =>
        audit.AppendAsync(new AuditEvent(Guid.NewGuid(), Clock.UtcNowMicros(), Clean(actor)!, Clean(action)!, Clean(target),
            success ? AuditEvent.Success : AuditEvent.Failure, Clean(detail), Clean(address)), ct);

    public async Task<Page<AuditEvent>> ListAsync(string? actor = null, string? action = null, PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        // Nothing recorded contains control characters or malformed Unicode (see Clean), so such a filter matches nothing.
        if ((actor is not null && !Validation.IsCleanText(actor)) || (action is not null && !Validation.IsCleanText(action)))
            return page.Build<AuditEvent>([]);
        return page.Build(await audit.ListAsync(actor, action, page.Slice, ct));
    }

    public static string? Clean(string? text)
    {
        if (text is null) return null;
        var chars = new System.Text.StringBuilder(Math.Min(text.Length, AuditEvent.MaxField));
        foreach (var rune in text.EnumerateRunes())
        {
            if (chars.Length >= AuditEvent.MaxField) break;
            var category = System.Text.Rune.GetUnicodeCategory(rune);
            var bad = rune.Value == 0xFFFD || category is System.Globalization.UnicodeCategory.Control
                or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator
                or System.Globalization.UnicodeCategory.ParagraphSeparator or System.Globalization.UnicodeCategory.PrivateUse
                or System.Globalization.UnicodeCategory.OtherNotAssigned;
            chars.Append(bad ? "?" : rune.ToString());
        }
        return chars.ToString();
    }
}

public sealed record ClientCreated(Client Client, string Secret);

/// <summary>
/// Service identities. Secrets are 256 random bits, so a plain SHA-256 is enough to store them (there is nothing to
/// brute-force) and verification is cheap; the secret is shown once, at creation or rotation, and cannot be read back.
/// </summary>
public sealed class ClientService(IClientRepository clients, IAppRepository apps, IRoleRepository roles)
{
    public const string SecretPrefix = "gks_";

    public async Task<Page<Client>> ListAsync(Guid? appId = null, PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        return page.Build(await clients.ListAsync(appId, page.Slice, ct));
    }

    public async Task<Client> GetAsync(Guid id, CancellationToken ct = default) =>
        await clients.GetAsync(id, ct) ?? throw new NotFoundException($"Client {id} not found.");

    public async Task<ClientCreated> CreateAsync(string? name, Guid appId, bool isActive = true, CancellationToken ct = default)
    {
        Validation.ClientName(name);
        var app = await apps.GetAsync(appId, ct) ?? throw new NotFoundException($"Application {appId} not found.");
        // Management stays with people; a machine identity must never hold the admin audience.
        if (string.Equals(app.Name, Reserved.AdminApp, StringComparison.OrdinalIgnoreCase))
            throw new ConflictException($"Application '{app.Name}' is reserved and cannot have service identities.");
        var secret = NewSecret();
        var now = Clock.UtcNowMicros();
        var created = await clients.AddAsync(new Client(Guid.NewGuid(), name!, appId, isActive, now, now), HashSecret(secret), ct);
        return new ClientCreated(created, secret);
    }

    public async Task<Client> UpdateAsync(Guid id, string? name, bool? isActive, CancellationToken ct = default)
    {
        Validation.ClientName(name);
        var existing = await GetAsync(id, ct);
        return await clients.UpdateAsync(existing with { Name = name!, IsActive = isActive ?? existing.IsActive, UpdatedAt = Clock.UtcNowMicros() }, ct)
            ?? throw new NotFoundException($"Client {id} not found.");
    }

    public Task<Client> PatchAsync(Guid id, string? name, bool? isActive, CancellationToken ct = default) => PatchGate.RunAsync(async () =>
        await UpdateAsync(id, name ?? (await GetAsync(id, ct)).Name, isActive, ct), ct);

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        if (!await clients.DeleteAsync(id, ct)) throw new NotFoundException($"Client {id} not found.");
    }

    /// <summary>Replaces the secret; the old one stops working at once. Returns the new secret.</summary>
    public async Task<string> RotateSecretAsync(Guid id, CancellationToken ct = default)
    {
        var secret = NewSecret();
        if (!await clients.SetSecretHashAsync(id, HashSecret(secret), Clock.UtcNowMicros(), ct))
            throw new NotFoundException($"Client {id} not found.");
        return secret;
    }

    public async Task<Page<Role>> ListRolesAsync(Guid clientId, PageQuery? page = null, CancellationToken ct = default)
    {
        page ??= PageQuery.Default;
        await GetAsync(clientId, ct);
        return page.Build(await clients.ListRolesAsync(clientId, page.Slice, ct));
    }

    public async Task AssignRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default)
    {
        var client = await GetAsync(clientId, ct);
        var role = await roles.GetAsync(roleId, ct) ?? throw new NotFoundException($"Role {roleId} not found.");
        // The token's audience is the client's application, so it can only carry that application's roles.
        if (role.AppId != client.AppId) throw new ConflictException("The role belongs to a different application than the client.");
        await clients.AssignRoleAsync(clientId, roleId, ct);
    }

    public async Task RevokeRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default)
    {
        await GetAsync(clientId, ct);
        if (!await clients.RevokeRoleAsync(clientId, roleId, ct))
            throw new NotFoundException($"Client {clientId} does not have role {roleId}.");
    }

    public static string NewSecret() =>
        SecretPrefix + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string HashSecret(string secret) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();

    public static bool SecretMatches(string storedHash, string secret) =>
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(storedHash), System.Text.Encoding.ASCII.GetBytes(HashSecret(secret)));
}

public sealed record ClientAuthResult(Client Client, App App, IReadOnlyList<string> Roles);

/// <summary>Client-credentials login. Like users, every failure is the same null so nothing about the client leaks.</summary>
public sealed class ClientAuthService(IClientRepository clients, IAppRepository apps)
{
    private static readonly string DummyHash = ClientService.HashSecret("dummy secret for unknown clients");

    public async Task<ClientAuthResult?> LoginAsync(string? clientId, string? secret, CancellationToken ct = default)
    {
        var wellFormed = Validation.LooksLikeUsername(clientId) && Validation.IsCleanText(clientId!)
                         && secret is { Length: >= 8 and <= 200 } && Validation.IsCleanText(secret);
        Client? client = null;
        string? stored = null;
        if (wellFormed)
        {
            client = await clients.GetByNameAsync(clientId!, ct);
            if (client is not null) stored = await clients.GetSecretHashAsync(client.Id, ct);
        }
        var matches = ClientService.SecretMatches(stored ?? DummyHash, wellFormed ? secret! : "malformed input placeholder");
        if (!wellFormed || client is null || stored is null || !matches || !client.IsActive) return null;

        var app = await apps.GetAsync(client.AppId, ct);
        if (app is null || string.Equals(app.Name, Reserved.AdminApp, StringComparison.OrdinalIgnoreCase)) return null;

        var names = new List<string>();
        const int pageSize = PageQuery.MaxLimit;
        while (true)
        {
            var batch = await clients.ListRolesAsync(client.Id, new Slice(names.Count, pageSize), ct);
            names.AddRange(batch.Select(r => r.Name));
            if (batch.Count < pageSize) break;
        }
        return names.Count == 0 ? null : new ClientAuthResult(client, app, names);
    }
}
