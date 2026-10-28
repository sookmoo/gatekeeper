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
    public Dictionary<Guid, Session> Sessions { get; } = [];
    public Dictionary<Guid, SessionHashes> SessionHashes { get; } = [];
    public Dictionary<Guid, Client> Clients { get; } = [];
    public Dictionary<Guid, string> ClientSecrets { get; } = [];
    public HashSet<(Guid ClientId, Guid RoleId)> ClientAssignments { get; } = [];

    internal static IReadOnlyList<T> Paged<T>(IEnumerable<T> ordered, Slice? slice) =>
        (slice is null ? ordered : ordered.Skip(slice.Offset).Take(slice.Take)).ToList();

    /// <summary>Throws PreconditionFailedException when a version is expected and the row has another (the caller holds the gate).</summary>
    internal static void CheckVersion(long current, long? expected)
    {
        if (expected is { } e && e != current) throw new PreconditionFailedException();
    }

    /// <summary>Raises the user's session cut-off (never lowers it). The caller holds the gate and has checked that the user exists.</summary>
    internal void RaiseCutOff(Guid userId, DateTimeOffset to)
    {
        var user = Users[userId];
        if (user.SessionsValidAfter is not { } current || current < to) Users[userId] = user with { SessionsValidAfter = to };
    }

    /// <summary>
    /// A password change's effect on sessions, in one step under the gate: revoke every other active session, then raise the cut-off (never lower), and re-stamp the kept session if the cut-off really rose
    /// and the session still counted; the cut-off is at least the clock reading at the end. The caller has checked that the user exists.
    /// </summary>
    internal void EndSessions(Guid userId, DateTimeOffset cut, DateTimeOffset at, Guid? keep)
    {
        foreach (var x in Sessions.Values.Where(x => x.UserId == userId && x.Id != keep && x.IsActive(at)).ToList())
            Sessions[x.Id] = x with { RevokedAt = at };
        // The last write: the cut-off is at least the caller's reading and at least the clock now, so a sign-in stamped in between is cut off too.
        var now = Application.Clock.UtcNowMicros();
        if (now > cut) cut = now;
        var user = Users[userId];
        var prev = user.SessionsValidAfter;
        if (prev is not { } p || cut > p)
        {
            Users[userId] = user with { SessionsValidAfter = cut };
            if (keep is { } k && Sessions.TryGetValue(k, out var kept) && kept.UserId == userId && kept.IsActive(at) && (prev is not { } old || kept.Stamp > old))
            {
                var restamp = cut.AddTicks(10);
                Sessions[k] = kept with { AuthenticatedAt = kept.Stamp > restamp ? kept.Stamp : restamp };
            }
        }
    }

    /// <summary>Whether the session counts after its user's cut-off (the caller holds the gate).</summary>
    internal bool CountsAfterCutOff(Session session) =>
        !Users.TryGetValue(session.UserId, out var user) || user.CountsAfterCutOff(session.Stamp);

    public void RemoveSessionsWhere(Func<Session, bool> match)
    {
        foreach (var x in Sessions.Values.Where(match).ToList())
        {
            Sessions.Remove(x.Id);
            SessionHashes.Remove(x.Id);
        }
    }

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
            app = app with { Version = 1 };
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

    public Task<App?> UpdateAsync(App app, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Apps.TryGetValue(app.Id, out var current)) return Task.FromResult<App?>(null);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            EnsureNameFree(app);
            var updated = app with { Version = current.Version + 1 };
            s.Apps[app.Id] = updated;
            return Task.FromResult<App?>(updated);
        }
    }

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Apps.TryGetValue(id, out var current)) return Task.FromResult(false);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            s.Apps.Remove(id);
            foreach (var role in s.Roles.Values.Where(r => r.AppId == id).ToList()) s.RemoveRole(role.Id);
            foreach (var client in s.Clients.Values.Where(c => c.AppId == id).ToList()) s.RemoveClient(client.Id);
            s.RemoveSessionsWhere(x => x.AppId == id);
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
            role = role with { Version = 1 };
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

    public Task<Role?> UpdateAsync(Role role, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Roles.TryGetValue(role.Id, out var current)) return Task.FromResult<Role?>(null);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            EnsureNameFree(role);
            var updated = role with { Version = current.Version + 1 };
            s.Roles[role.Id] = updated;
            return Task.FromResult<Role?>(updated);
        }
    }

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Roles.TryGetValue(id, out var current)) return Task.FromResult(false);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            s.RemoveRole(id);
            return Task.FromResult(true);
        }
    }

    public Task<IReadOnlyList<RevokedSession>?> DeleteEndingSessionsAsync(Guid id, long? expectedVersion, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Roles.TryGetValue(id, out var current)) return Task.FromResult<IReadOnlyList<RevokedSession>?>(null);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            var ended = new List<RevokedSession>();
            foreach (var userId in s.Assignments.Where(a => a.RoleId == id).Select(a => a.UserId).ToList())
            {
                if (s.Assignments.Any(a => a.UserId == userId && a.RoleId != id && s.Roles.TryGetValue(a.RoleId, out var other) && other.AppId == current.AppId)) continue;
                foreach (var x in s.Sessions.Values.Where(x => x.UserId == userId && x.AppId == current.AppId && x.IsActive(now)).ToList())
                {
                    s.Sessions[x.Id] = x with { RevokedAt = now };
                    ended.Add(new RevokedSession(userId, x.Id));
                }
            }
            s.RemoveRole(id);
            return Task.FromResult<IReadOnlyList<RevokedSession>?>(ended);
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
            user = user with { Version = 1 };
            s.Users[user.Id] = user;
            return Task.FromResult(user);
        }
    }

    public Task<User?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Users.GetValueOrDefault(id));
    }

    public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, UserKind? kind = null, string? usernamePrefix = null, string? emailPrefix = null,
        bool? usable = null, DateTimeOffset? now = null, Slice? slice = null, CancellationToken ct = default)
    {
        var at = now ?? Clock.UtcNowMicros();
        lock (s.Gate)
            return Task.FromResult<IReadOnlyList<User>>(
                InMemoryStore.Paged(s.Users.Values
                    .Where(u => active is null || u.IsActive == active)
                    .Where(u => username is null || InMemoryAppRepository.Same(u.Username, username))
                    .Where(u => kind is null || u.Kind == kind)
                    .Where(u => usernamePrefix is null || u.Username.StartsWith(usernamePrefix, StringComparison.OrdinalIgnoreCase))
                    .Where(u => emailPrefix is null || u.Email.StartsWith(emailPrefix, StringComparison.OrdinalIgnoreCase))
                    .Where(u => usable is null || u.IsUsable(at) == usable)
                    .OrderBy(u => u.Username), slice));
    }

    public Task<User?> UpdateAsync(User user, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.TryGetValue(user.Id, out var current)) return Task.FromResult<User?>(null);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            EnsureUnique(user);
            var cut = user.SessionsValidAfter is { } asked && (current.SessionsValidAfter is not { } had || had < asked) ? asked : current.SessionsValidAfter;
            var updated = user with { Version = current.Version + 1, SessionsValidAfter = cut };
            s.Users[user.Id] = updated;
            return Task.FromResult<User?>(updated);
        }
    }

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.TryGetValue(id, out var current)) return Task.FromResult(false);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            s.Users.Remove(id);
            s.Assignments.RemoveWhere(a => a.UserId == id);
            s.Credentials.Remove(id);
            s.RemoveSessionsWhere(x => x.UserId == id);
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
    public Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.ContainsKey(userId)) throw new NotFoundException($"User {userId} not found.");
            var existed = s.Credentials.ContainsKey(userId);
            s.Credentials[userId] = hash;
            if (cutOffAt is { } cut && existed) s.EndSessions(userId, cut, at, null);
        }
        return Task.CompletedTask;
    }

    public Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Credentials.GetValueOrDefault(userId));
    }

    public Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Credentials.TryGetValue(userId, out var current) || current != expectedHash) return Task.FromResult(false);
            s.Credentials[userId] = newHash;
            if (cutOffAt is { } cut && s.Users.ContainsKey(userId)) s.EndSessions(userId, cut, at, keepSession);
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
            client = client with { Version = 1 };
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

    public Task<Client?> UpdateAsync(Client client, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Clients.TryGetValue(client.Id, out var current)) return Task.FromResult<Client?>(null);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            EnsureNameFree(client);
            var updated = current with { Name = client.Name, IsActive = client.IsActive, UpdatedAt = client.UpdatedAt, Version = current.Version + 1 };
            s.Clients[client.Id] = updated;
            return Task.FromResult<Client?>(updated);
        }
    }

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Clients.TryGetValue(id, out var current)) return Task.FromResult(false);
            InMemoryStore.CheckVersion(current.Version, expectedVersion);
            s.RemoveClient(id);
            return Task.FromResult(true);
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

public sealed class InMemorySessionRepository(InMemoryStore s) : ISessionRepository
{
    public Task AddAsync(Session session, string tokenHash, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.ContainsKey(session.UserId)) throw new NotFoundException($"User {session.UserId} not found.");
            if (!s.Apps.ContainsKey(session.AppId)) throw new NotFoundException($"Application {session.AppId} not found.");
            if (s.Sessions.ContainsKey(session.Id)) throw new ConflictException($"Session {session.Id} already exists.");
            s.Sessions[session.Id] = session with { AuthenticatedAt = session.Stamp };
            s.SessionHashes[session.Id] = new SessionHashes(tokenHash, null);
        }
        return Task.CompletedTask;
    }

    public async Task<bool> AddForCredentialAsync(Session session, string tokenHash, string credentialHash, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Credentials.TryGetValue(session.UserId, out var current) || current != credentialHash) return false;
            AddAsync(session, tokenHash, ct).GetAwaiter().GetResult(); // completes synchronously under the gate (the lock is re-entrant)
        }
        await Task.CompletedTask;
        return true;
    }

    public Task<Session?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.Sessions.GetValueOrDefault(id));
    }

    public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default)
    {
        lock (s.Gate) return Task.FromResult(s.SessionHashes.TryGetValue(id, out var h) ? h : null);
    }

    public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid userId, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default)
    {
        lock (s.Gate)
            return Task.FromResult(InMemoryStore.Paged(
                s.Sessions.Values.Where(x => x.UserId == userId && x.IsActive(now) && s.CountsAfterCutOff(x)).OrderByDescending(x => x.CreatedAt).ThenByDescending(x => x.Id), slice));
    }

    public Task<bool> RotateAsync(Guid id, string expectedHash, string newHash, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Sessions.TryGetValue(id, out var session) || !session.IsActive(now) || !s.CountsAfterCutOff(session)) return Task.FromResult(false);
            if (!s.SessionHashes.TryGetValue(id, out var h) || h.Current != expectedHash) return Task.FromResult(false);
            s.SessionHashes[id] = new SessionHashes(newHash, h.Current);
            s.Sessions[id] = session with { LastUsedAt = now };
            return Task.FromResult(true);
        }
    }

    public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Sessions.TryGetValue(id, out var session)) return Task.FromResult(false);
            if (session.RevokedAt is null) s.Sessions[id] = session with { RevokedAt = now };
            return Task.FromResult(true);
        }
    }

    public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Sessions.TryGetValue(sessionId, out var session) || session.UserId != userId) return Task.FromResult(false);
            if (session.RevokedAt is null) s.Sessions[sessionId] = session with { RevokedAt = now };
            return Task.FromResult(true);
        }
    }

    public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var active = s.Sessions.Values.Where(x => x.UserId == userId && x.IsActive(now)).ToList();
            foreach (var x in active) s.Sessions[x.Id] = x with { RevokedAt = now };
            return Task.FromResult(active.Count);
        }
    }

    public Task<int> RevokeAllAndCutOffAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            if (!s.Users.ContainsKey(userId)) return Task.FromResult(0);
            s.RaiseCutOff(userId, now);
            var active = s.Sessions.Values.Where(x => x.UserId == userId && x.IsActive(now)).ToList();
            foreach (var x in active) s.Sessions[x.Id] = x with { RevokedAt = now };
            return Task.FromResult(active.Count);
        }
    }

    public Task<int> RevokeAllForUserExceptAsync(Guid userId, Guid keep, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var active = s.Sessions.Values.Where(x => x.UserId == userId && x.Id != keep && x.IsActive(now)).ToList();
            foreach (var x in active) s.Sessions[x.Id] = x with { RevokedAt = now };
            return Task.FromResult(active.Count);
        }
    }

    public Task<int> RevokeAllForUserInAppAsync(Guid userId, Guid appId, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var active = s.Sessions.Values.Where(x => x.UserId == userId && x.AppId == appId && x.IsActive(now)).ToList();
            foreach (var x in active) s.Sessions[x.Id] = x with { RevokedAt = now };
            return Task.FromResult(active.Count);
        }
    }

    public Task<int> CapExpiryForUserAsync(Guid userId, DateTimeOffset endsAt, DateTimeOffset now, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var active = s.Sessions.Values.Where(x => x.UserId == userId && x.IsActive(now) && x.ExpiresAt > endsAt).ToList();
            foreach (var x in active) s.Sessions[x.Id] = x with { ExpiresAt = endsAt };
            return Task.FromResult(active.Count);
        }
    }

    public Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var old = s.Sessions.Values.Where(x => x.ExpiresAt < expiredBefore).Select(x => x.Id).ToList();
            foreach (var id in old) { s.Sessions.Remove(id); s.SessionHashes.Remove(id); }
            return Task.FromResult(old.Count);
        }
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

    public Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, AuditKey? after = null, int? take = null, CancellationToken ct = default)
    {
        lock (s.Gate)
        {
            var q = s.Audit.AsEnumerable();
            if (after is { } a) q = q.Where(e => AuditKey.Compare(new AuditKey(e.At, e.Id), a) < 0);
            if (actor is not null) q = q.Where(e => e.Actor == actor);
            if (action is not null) q = q.Where(e => e.Action == action);
            var ordered = q.OrderByDescending(e => e.At.UtcTicks).ThenByDescending(e => e.Id, Comparer<Guid>.Create(AuditKey.CompareIds));
            return Task.FromResult<IReadOnlyList<AuditEvent>>((take is { } n ? ordered.Take(n) : ordered).ToList());
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
        .AddSingleton<ISessionRepository, InMemorySessionRepository>()
        .AddSingleton<IAuditRepository, InMemoryAuditRepository>()
        .AddSingleton<IReadinessProbe, AlwaysReady>();
}

internal sealed class AlwaysReady : IReadinessProbe
{
    public Task<bool> IsReadyAsync(CancellationToken ct = default) => Task.FromResult(true);
}
