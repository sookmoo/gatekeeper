using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Infrastructure;

/// <summary>Shared state for the in-memory repositories. All access goes through <see cref="Gate"/>.</summary>
public sealed class InMemoryStore
{
    public object Gate { get; } = new();
    public Dictionary<Guid, App> Apps { get; } = [];
    public Dictionary<Guid, Role> Roles { get; } = [];
    public Dictionary<Guid, User> Users { get; } = [];
    public HashSet<(Guid UserId, Guid RoleId)> Assignments { get; } = [];
    public Dictionary<Guid, string> Credentials { get; } = [];
    public List<AuditEvent> Audit { get; } = [];
    public Dictionary<Guid, Client> Clients { get; } = [];
    public Dictionary<Guid, string> ClientSecrets { get; } = [];
    public HashSet<(Guid ClientId, Guid RoleId)> ClientAssignments { get; } = [];

    internal static IReadOnlyList<T> Paged<T>(IEnumerable<T> ordered, Slice? slice) =>
        (slice is null ? ordered : ordered.Skip(slice.Offset).Take(slice.Take)).ToList();

    public void RemoveClient(Guid clientId)
    {
        Clients.Remove(clientId);
        ClientSecrets.Remove(clientId);
        ClientAssignments.RemoveWhere(a => a.ClientId == clientId);
    }

    public void RemoveRole(Guid roleId)
    {
        Roles.Remove(roleId);
        Assignments.RemoveWhere(a => a.RoleId == roleId);
        ClientAssignments.RemoveWhere(a => a.RoleId == roleId);
    }
}

public sealed class InMemoryAppRepository(InMemoryStore s) : IAppRepository
{
    public Task<App> AddAsync(App app, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            EnsureNameFree(app);
            s.Apps[app.Id] = app;
            return Task.FromResult(app);
        }
    }

    public Task<App?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Apps.GetValueOrDefault(id));
    }

    public Task<App?> GetByNameAsync(string name, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Apps.Values.FirstOrDefault(a => Same(a.Name, name)));
    }

    public Task<IReadOnlyList<App>> ListAsync(Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult<IReadOnlyList<App>>(InMemoryStore.Paged(s.Apps.Values.OrderBy(a => a.Name), slice));
    }

    public Task<App?> UpdateAsync(App app, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Apps.ContainsKey(app.Id)) return Task.FromResult<App?>(null);
            EnsureNameFree(app);
            s.Apps[app.Id] = app;
            return Task.FromResult<App?>(app);
        }
    }

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Apps.Remove(id)) return Task.FromResult(false);
            foreach (var role in s.Roles.Values.Where(r => r.AppId == id).ToList()) s.RemoveRole(role.Id);
            foreach (var client in s.Clients.Values.Where(c => c.AppId == id).ToList()) s.RemoveClient(client.Id);
            return Task.FromResult(true);
        }
    }

    private void EnsureNameFree(App app)
    {
        if (s.Apps.Values.Any(a => a.Id != app.Id && Same(a.Name, app.Name)))
            throw new ConflictException($"Application '{app.Name}' already exists.");
    }

    internal static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}

public sealed class InMemoryRoleRepository(InMemoryStore s) : IRoleRepository
{
    public Task<Role> AddAsync(Role role, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Apps.ContainsKey(role.AppId)) throw new NotFoundException($"Application {role.AppId} not found.");
            EnsureNameFree(role);
            s.Roles[role.Id] = role;
            return Task.FromResult(role);
        }
    }

    public Task<Role?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Roles.GetValueOrDefault(id));
    }

    public Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult<IReadOnlyList<Role>>(
                InMemoryStore.Paged(s.Roles.Values.Where(r => r.AppId == appId).OrderBy(r => r.Name), slice));
    }

    public Task<Role?> UpdateAsync(Role role, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Roles.ContainsKey(role.Id)) return Task.FromResult<Role?>(null);
            EnsureNameFree(role);
            s.Roles[role.Id] = role;
            return Task.FromResult<Role?>(role);
        }
    }

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var existed = s.Roles.ContainsKey(id);
            s.RemoveRole(id);
            return Task.FromResult(existed);
        }
    }

    private void EnsureNameFree(Role role)
    {
        if (s.Roles.Values.Any(r => r.Id != role.Id && r.AppId == role.AppId && InMemoryAppRepository.Same(r.Name, role.Name)))
            throw new ConflictException($"Role '{role.Name}' already exists in this application.");
    }
}

public sealed class InMemoryUserRepository(InMemoryStore s) : IUserRepository
{
    public Task<User> AddAsync(User user, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            EnsureUnique(user);
            s.Users[user.Id] = user;
            return Task.FromResult(user);
        }
    }

    public Task<User?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Users.GetValueOrDefault(id));
    }

    public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult<IReadOnlyList<User>>(
                InMemoryStore.Paged(s.Users.Values
                    .Where(u => active is null || u.IsActive == active)
                    .Where(u => username is null || InMemoryAppRepository.Same(u.Username, username))
                    .OrderBy(u => u.Username), slice));
    }

    public Task<User?> UpdateAsync(User user, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.ContainsKey(user.Id)) return Task.FromResult<User?>(null);
            EnsureUnique(user);
            s.Users[user.Id] = user;
            return Task.FromResult<User?>(user);
        }
    }

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.Remove(id)) return Task.FromResult(false);
            s.Assignments.RemoveWhere(a => a.UserId == id);
            s.Credentials.Remove(id);
            return Task.FromResult(true);
        }
    }

    public Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.ContainsKey(userId)) throw new NotFoundException($"User {userId} not found.");
            if (!s.Roles.ContainsKey(roleId)) throw new NotFoundException($"Role {roleId} not found.");
            s.Assignments.Add((userId, roleId));
        }
        return Task.CompletedTask;
    }

    public Task<bool> RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Assignments.Remove((userId, roleId)));
    }

    public Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult<IReadOnlyList<Role>>(
                InMemoryStore.Paged(s.Assignments
                    .Where(a => a.UserId == userId)
                    .Select(a => s.Roles.GetValueOrDefault(a.RoleId))
                    .OfType<Role>()
                    .Where(r => appId is null || r.AppId == appId)
                    .OrderBy(r => r.Name).ThenBy(r => r.Id), slice));
    }

    public Task<int> CountActiveWithRoleAsync(Guid roleId, Guid? excludingUserId = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult(s.Assignments.Count(a =>
                a.RoleId == roleId && a.UserId != excludingUserId && s.Users.TryGetValue(a.UserId, out var u) && u.IsActive));
    }

    private void EnsureUnique(User user)
    {
        foreach (var other in s.Users.Values.Where(u => u.Id != user.Id))
        {
            if (InMemoryAppRepository.Same(other.Username, user.Username))
                throw new ConflictException($"Username '{user.Username}' is already taken.");
            if (InMemoryAppRepository.Same(other.Email, user.Email))
                throw new ConflictException($"Email '{user.Email}' is already in use.");
        }
    }
}

public sealed class InMemoryCredentialRepository(InMemoryStore s) : ICredentialRepository
{
    public Task SetAsync(Guid userId, string hash, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.ContainsKey(userId)) throw new NotFoundException($"User {userId} not found.");
            s.Credentials[userId] = hash;
        }
        return Task.CompletedTask;
    }

    public Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Credentials.GetValueOrDefault(userId));
    }

    public Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Credentials.TryGetValue(userId, out var current) || current != expectedHash) return Task.FromResult(false);
            s.Credentials[userId] = newHash;
            return Task.FromResult(true);
        }
    }
}

public sealed class InMemoryClientRepository(InMemoryStore s) : IClientRepository
{
    public Task<Client> AddAsync(Client client, string secretHash, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Apps.ContainsKey(client.AppId)) throw new NotFoundException($"Application {client.AppId} not found.");
            EnsureNameFree(client);
            s.Clients[client.Id] = client;
            s.ClientSecrets[client.Id] = secretHash;
            return Task.FromResult(client);
        }
    }

    public Task<Client?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Clients.GetValueOrDefault(id));
    }

    public Task<Client?> GetByNameAsync(string name, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Clients.Values.FirstOrDefault(c => InMemoryAppRepository.Same(c.Name, name)));
    }

    public Task<IReadOnlyList<Client>> ListAsync(Guid? appId = null, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult(InMemoryStore.Paged(
                s.Clients.Values.Where(c => appId is null || c.AppId == appId).OrderBy(c => c.Name), slice));
    }

    public Task<Client?> UpdateAsync(Client client, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Clients.TryGetValue(client.Id, out var current)) return Task.FromResult<Client?>(null);
            EnsureNameFree(client);
            var updated = current with { Name = client.Name, IsActive = client.IsActive, UpdatedAt = client.UpdatedAt };
            s.Clients[client.Id] = updated;
            return Task.FromResult<Client?>(updated);
        }
    }

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var existed = s.Clients.ContainsKey(id);
            s.RemoveClient(id);
            return Task.FromResult(existed);
        }
    }

    public Task<bool> SetSecretHashAsync(Guid id, string secretHash, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Clients.ContainsKey(id)) return Task.FromResult(false);
            s.ClientSecrets[id] = secretHash;
            return Task.FromResult(true);
        }
    }

    public Task<string?> GetSecretHashAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.ClientSecrets.GetValueOrDefault(id));
    }

    public Task AssignRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Clients.ContainsKey(clientId)) throw new NotFoundException($"Client {clientId} not found.");
            if (!s.Roles.ContainsKey(roleId)) throw new NotFoundException($"Role {roleId} not found.");
            s.ClientAssignments.Add((clientId, roleId));
        }
        return Task.CompletedTask;
    }

    public Task<bool> RevokeRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.ClientAssignments.Remove((clientId, roleId)));
    }

    public Task<IReadOnlyList<Role>> ListRolesAsync(Guid clientId, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult(InMemoryStore.Paged(
                s.ClientAssignments.Where(a => a.ClientId == clientId).Select(a => s.Roles[a.RoleId]).OrderBy(r => r.Name).ThenBy(r => r.Id), slice));
    }

    private void EnsureNameFree(Client client)
    {
        if (s.Clients.Values.Any(c => c.Id != client.Id && InMemoryAppRepository.Same(c.Name, client.Name)))
            throw new ConflictException($"Client '{client.Name}' already exists.");
    }
}

public sealed class InMemoryAuditRepository(InMemoryStore s) : IAuditRepository
{
    public Task AppendAsync(AuditEvent entry, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (s.Audit.Any(e => e.Id == entry.Id)) throw new ConflictException($"Audit event {entry.Id} already exists.");
            s.Audit.Add(entry);
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var q = s.Audit.AsEnumerable();
            if (actor is not null) q = q.Where(e => e.Actor == actor);
            if (action is not null) q = q.Where(e => e.Action == action);
            return Task.FromResult(InMemoryStore.Paged(q.OrderByDescending(e => e.At).ThenByDescending(e => e.Id), slice));
        }
    }
}

public static class InMemoryServiceCollectionExtensions
{
    public static IServiceCollection AddInMemoryStore(this IServiceCollection services) => services
        .AddSingleton<InMemoryStore>()
        .AddSingleton<IAppRepository, InMemoryAppRepository>()
        .AddSingleton<IRoleRepository, InMemoryRoleRepository>()
        .AddSingleton<IUserRepository, InMemoryUserRepository>()
        .AddSingleton<ICredentialRepository, InMemoryCredentialRepository>()
        .AddSingleton<IClientRepository, InMemoryClientRepository>()
        .AddSingleton<IAuditRepository, InMemoryAuditRepository>()
        .AddSingleton<IReadinessProbe, AlwaysReady>();
}

internal sealed class AlwaysReady : IReadinessProbe
{
    public Task<bool> IsReadyAsync(CancellationToken ct = default) => Task.FromResult(true);
}
