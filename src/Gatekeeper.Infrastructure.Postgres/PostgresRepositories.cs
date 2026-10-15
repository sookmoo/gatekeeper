using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Gatekeeper.Infrastructure.Postgres;

using Factory = IDbContextFactory<GatekeeperDbContext>;
using Translator = Func<GatekeeperDbContext, PostgresException, Task<GatekeeperException?>>;

/// <summary>
/// Opens a short-lived context per operation and applies the port contract's error rules:
/// unique/FK violations become Conflict/NotFound, and connection or overload failures become
/// <see cref="StoreUnavailableException"/> (HTTP 503). Anything else is a bug and propagates.
/// </summary>
internal static class PagingExtensions
{
    public static IQueryable<T> Page<T>(this IQueryable<T> ordered, Slice? slice) =>
        slice is null ? ordered : ordered.Skip(slice.Offset).Take(slice.Take);
}

public abstract class PostgresRepository(Factory factory)
{
    private const string UniqueViolation = "23505";
    private const string ForeignKeyViolation = "23503";

    protected async Task<T> Run<T>(Func<GatekeeperDbContext, Task<T>> operation, Translator? translate = null, CancellationToken ct = default)
    {
        try
        {
            await using var db = await factory.CreateDbContextAsync(ct);
            try
            {
                return await operation(db);
            }
            catch (Exception ex) when (translate is not null && ConstraintViolation(ex) is { } pg)
            {
                // Translate on a fresh context: the failed one may hold tracked entities in a bad state.
                await using var lookup = await factory.CreateDbContextAsync(ct);
                throw await translate(lookup, pg)
                      ?? throw new InvalidOperationException("Unmapped database constraint violation.", ex);
            }
        }
        catch (Exception ex) when (IsUnavailable(ex))
        {
            throw new StoreUnavailableException("The data store is currently unavailable.", ex);
        }
    }

    private static PostgresException? ConstraintViolation(Exception ex) =>
        (ex is DbUpdateException { InnerException: PostgresException inner } ? inner : ex as PostgresException) is
        { SqlState: UniqueViolation or ForeignKeyViolation } pg
            ? pg
            : null;

    // EF wraps provider failures (for example in "likely due to a transient failure"), so walk the chain.
    private static bool IsUnavailable(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
        {
            switch (ex)
            {
                // Transient (connection class, shutdown, too many connections, ...) or a schema that is not there yet
                // (undefined table/column: not migrated, so every request would fail the same way until `migrate` runs).
                case PostgresException pg: return pg.IsTransient || pg.SqlState is "42P01" or "42703";
                case NpgsqlException: return true;                // could not connect, I/O failure
                // A parameter of a type from an extension (citext) that the database does not have yet: not migrated.
                case NotSupportedException when ex.Message.Contains("could not be found in the types that were loaded"): return true;
                case TimeoutException: return true;
            }
        }
        return false;
    }
}

public sealed class PostgresAppRepository(Factory factory) : PostgresRepository(factory), IAppRepository
{
    public Task<App> AddAsync(App app, CancellationToken ct = default) => Run(async db =>
    {
        db.Apps.Add(app);
        await db.SaveChangesAsync(ct);
        return app;
    }, Translate(app), ct);

    public Task<App?> GetAsync(Guid id, CancellationToken ct = default) =>
        Run(db => db.Apps.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, ct), ct: ct);

    public Task<App?> GetByNameAsync(string name, CancellationToken ct = default) =>
        Run(db => db.Apps.AsNoTracking().FirstOrDefaultAsync(a => a.Name == name, ct), ct: ct); // citext: case-insensitive

    public Task<IReadOnlyList<App>> ListAsync(Slice? slice = null, CancellationToken ct = default) =>
        Run<IReadOnlyList<App>>(async db => await db.Apps.AsNoTracking().OrderBy(a => a.Name).Page(slice).ToListAsync(ct), ct: ct);

    public Task<App?> UpdateAsync(App app, CancellationToken ct = default) => Run<App?>(async db =>
    {
        db.Apps.Update(app);
        try
        {
            await db.SaveChangesAsync(ct);
            return app;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null; // row no longer exists
        }
    }, Translate(app), ct);

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default) =>
        Run(async db => await db.Apps.Where(a => a.Id == id).ExecuteDeleteAsync(ct) > 0, ct: ct);

    private static Translator Translate(App app) => (_, pg) => Task.FromResult<GatekeeperException?>(
        pg.ConstraintName == Names.AppNameIndex ? new ConflictException($"Application '{app.Name}' already exists.") : null);
}

public sealed class PostgresRoleRepository(Factory factory) : PostgresRepository(factory), IRoleRepository
{
    public Task<Role> AddAsync(Role role, CancellationToken ct = default) => Run(async db =>
    {
        db.Roles.Add(role);
        await db.SaveChangesAsync(ct);
        return role;
    }, Translate(role), ct);

    public Task<Role?> GetAsync(Guid id, CancellationToken ct = default) =>
        Run(db => db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct), ct: ct);

    public Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<Role>>(async db =>
        await db.Roles.AsNoTracking().Where(r => r.AppId == appId).OrderBy(r => r.Name).ThenBy(r => r.Id).Page(slice).ToListAsync(ct), ct: ct);

    public Task<Role?> UpdateAsync(Role role, CancellationToken ct = default) => Run<Role?>(async db =>
    {
        db.Roles.Update(role);
        try
        {
            await db.SaveChangesAsync(ct);
            return role;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null;
        }
    }, Translate(role), ct);

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default) =>
        Run(async db => await db.Roles.Where(r => r.Id == id).ExecuteDeleteAsync(ct) > 0, ct: ct);

    private static Translator Translate(Role role) => (_, pg) => Task.FromResult<GatekeeperException?>(pg.ConstraintName switch
    {
        Names.RoleNameIndex => new ConflictException($"Role '{role.Name}' already exists in this application."),
        Names.RoleAppFk => new NotFoundException($"Application {role.AppId} not found."),
        _ => null,
    });
}

public sealed class PostgresUserRepository(Factory factory) : PostgresRepository(factory), IUserRepository
{
    public Task<User> AddAsync(User user, CancellationToken ct = default) => Run(async db =>
    {
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        return user;
    }, TranslateUnique(user), ct);

    public Task<User?> GetAsync(Guid id, CancellationToken ct = default) =>
        Run(db => db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct), ct: ct);

    public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, UserKind? kind = null, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<User>>(async db =>
    {
        var query = db.Users.AsNoTracking();
        if (active is not null) query = query.Where(u => u.IsActive == active);
        if (username is not null) query = query.Where(u => u.Username == username); // citext: case-insensitive
        if (kind is not null) query = query.Where(u => u.Kind == kind);
        return await query.OrderBy(u => u.Username).Page(slice).ToListAsync(ct);
    }, ct: ct);

    public Task<User?> UpdateAsync(User user, CancellationToken ct = default) => Run<User?>(async db =>
    {
        db.Users.Update(user);
        try
        {
            await db.SaveChangesAsync(ct);
            return user;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null;
        }
    }, TranslateUnique(user), ct);

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default) =>
        Run(async db => await db.Users.Where(u => u.Id == id).ExecuteDeleteAsync(ct) > 0, ct: ct);

    public Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default) => Run(async db =>
    {
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO user_roles (user_id, role_id) VALUES ({userId}, {roleId}) ON CONFLICT DO NOTHING", ct);
        return 0;
    }, async (lookup, pg) =>
    {
        if (pg.SqlState != "23503") return null;
        // When both are missing, report the user first (same precedence as the in-memory store).
        if (!await lookup.Users.AnyAsync(u => u.Id == userId)) return new NotFoundException($"User {userId} not found.");
        return new NotFoundException($"Role {roleId} not found.");
    }, ct: ct);

    public Task<bool> RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default) => Run(async db =>
        await db.UserRoles.Where(x => x.UserId == userId && x.RoleId == roleId).ExecuteDeleteAsync(ct) > 0, ct: ct);

    public Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<Role>>(async db =>
    {
        var query = db.UserRoles.AsNoTracking()
            .Where(x => x.UserId == userId)
            .Join(db.Roles, x => x.RoleId, r => r.Id, (_, r) => r);
        if (appId is not null) query = query.Where(r => r.AppId == appId);
        return await query.OrderBy(r => r.Name).ThenBy(r => r.Id).Page(slice).ToListAsync(ct);
    }, ct: ct);

    public Task<int> CountActiveWithRoleAsync(Guid roleId, Guid? excludingUserId = null, CancellationToken ct = default) => Run(db =>
        db.UserRoles.AsNoTracking()
            .Where(x => x.RoleId == roleId && x.UserId != excludingUserId)
            .Join(db.Users.Where(u => u.IsActive), x => x.UserId, u => u.Id, (x, _) => x)
            .CountAsync(ct), ct: ct);

    // Both unique indexes may be violated at once and Postgres reports only one. Report the username
    // first, like the in-memory store, by checking it explicitly.
    private static Translator TranslateUnique(User user) => async (lookup, pg) =>
    {
        if (pg.ConstraintName is not (Names.UsernameIndex or Names.EmailIndex)) return null;
        if (await lookup.Users.AnyAsync(u => u.Id != user.Id && u.Username == user.Username))
            return new ConflictException($"Username '{user.Username}' is already taken.");
        return new ConflictException($"Email '{user.Email}' is already in use.");
    };
}

public sealed class PostgresCredentialRepository(Factory factory) : PostgresRepository(factory), ICredentialRepository
{
    public Task SetAsync(Guid userId, string hash, DateTimeOffset at, CancellationToken ct = default) => Run(async db =>
    {
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO user_credentials (user_id, hash, updated_at) VALUES ({userId}, {hash}, {at}) ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash, updated_at = EXCLUDED.updated_at", ct);
        return 0;
    }, (_, pg) => Task.FromResult<GatekeeperException?>(
        pg.ConstraintName == Names.CredentialUserFk ? new NotFoundException($"User {userId} not found.") : null), ct);

    public Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE user_credentials SET hash = {newHash}, updated_at = {at} WHERE user_id = {userId} AND hash = {expectedHash}", ct) > 0, ct: ct);

    public Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default) =>
        Run<string?>(db => db.Credentials.AsNoTracking().Where(c => c.UserId == userId).Select(c => c.Hash).FirstOrDefaultAsync(ct), ct: ct);
}

/// <summary>INSERT and SELECT only. The table also rejects UPDATE, DELETE and TRUNCATE with a trigger (see the migration).</summary>
public sealed class PostgresAuditRepository(Factory factory) : PostgresRepository(factory), IAuditRepository
{
    public Task AppendAsync(AuditEvent entry, CancellationToken ct = default) => Run(async db =>
    {
        db.AuditEvents.Add(entry);
        await db.SaveChangesAsync(ct);
        return 0;
    }, ct: ct);

    public Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<AuditEvent>>(async db =>
    {
        // Stored text never contains NUL or malformed Unicode (Postgres cannot even compare against it): nothing matches.
        if ((actor is not null && !Validation.IsCleanText(actor)) || (action is not null && !Validation.IsCleanText(action))) return [];
        var q = db.AuditEvents.AsNoTracking();
        if (actor is not null) q = q.Where(e => e.Actor == actor);
        if (action is not null) q = q.Where(e => e.Action == action);
        return await q.OrderByDescending(e => e.At).ThenByDescending(e => e.Id).Page(slice).ToListAsync(ct);
    }, ct: ct);
}

public sealed class PostgresClientRepository(Factory factory) : PostgresRepository(factory), IClientRepository
{
    public Task<Client> AddAsync(Client client, string secretHash, CancellationToken ct = default) => Run(async db =>
    {
        db.Clients.Add(client);
        db.ClientSecrets.Add(new ClientSecretRow(client.Id, secretHash, client.CreatedAt));
        await db.SaveChangesAsync(ct);
        return client;
    }, (_, pg) => Task.FromResult<GatekeeperException?>(pg.ConstraintName switch
    {
        Names.ClientNameIndex => new ConflictException($"Client '{client.Name}' already exists."),
        Names.ClientAppFk => new NotFoundException($"Application {client.AppId} not found."),
        _ => null,
    }), ct);

    public Task<Client?> GetAsync(Guid id, CancellationToken ct = default) =>
        Run(db => db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct), ct: ct);

    public Task<Client?> GetByNameAsync(string name, CancellationToken ct = default) =>
        Run(db => db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Name == name, ct), ct: ct); // citext

    public Task<IReadOnlyList<Client>> ListAsync(Guid? appId = null, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<Client>>(async db =>
    {
        var q = db.Clients.AsNoTracking();
        if (appId is not null) q = q.Where(c => c.AppId == appId);
        return await q.OrderBy(c => c.Name).ThenBy(c => c.Id).Page(slice).ToListAsync(ct);
    }, ct: ct);

    public Task<Client?> UpdateAsync(Client client, CancellationToken ct = default) => Run<Client?>(async db =>
    {
        // Only these columns may change: the application is fixed at creation.
        var rows = await db.Clients.Where(c => c.Id == client.Id).ExecuteUpdateAsync(set => set
            .SetProperty(c => c.Name, client.Name)
            .SetProperty(c => c.IsActive, client.IsActive)
            .SetProperty(c => c.UpdatedAt, client.UpdatedAt), ct);
        return rows == 0 ? null : await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == client.Id, ct);
    }, (_, pg) => Task.FromResult<GatekeeperException?>(
        pg.ConstraintName == Names.ClientNameIndex ? new ConflictException($"Client '{client.Name}' already exists.") : null), ct);

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default) =>
        Run(async db => await db.Clients.Where(c => c.Id == id).ExecuteDeleteAsync(ct) > 0, ct: ct);

    // Every client has a secret row from creation, so a plain UPDATE both rotates and detects a missing client.
    public Task<bool> SetSecretHashAsync(Guid id, string secretHash, DateTimeOffset at, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE client_secrets SET hash = {secretHash}, updated_at = {at} WHERE client_id = {id}", ct) > 0, ct: ct);

    public Task<string?> GetSecretHashAsync(Guid id, CancellationToken ct = default) =>
        Run<string?>(db => db.ClientSecrets.AsNoTracking().Where(c => c.ClientId == id).Select(c => c.Hash).FirstOrDefaultAsync(ct), ct: ct);

    public Task AssignRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default) => Run(async db =>
    {
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO client_roles (client_id, role_id) VALUES ({clientId}, {roleId}) ON CONFLICT DO NOTHING", ct);
        return 0;
    }, async (lookup, pg) =>
    {
        if (pg.SqlState != "23503") return null;
        if (!await lookup.Clients.AnyAsync(c => c.Id == clientId)) return new NotFoundException($"Client {clientId} not found.");
        return new NotFoundException($"Role {roleId} not found.");
    }, ct);

    public Task<bool> RevokeRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default) => Run(async db =>
        await db.ClientRoles.Where(x => x.ClientId == clientId && x.RoleId == roleId).ExecuteDeleteAsync(ct) > 0, ct: ct);

    public Task<IReadOnlyList<Role>> ListRolesAsync(Guid clientId, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<Role>>(async db =>
        await db.ClientRoles.AsNoTracking().Where(x => x.ClientId == clientId)
            .Join(db.Roles, x => x.RoleId, r => r.Id, (_, r) => r)
            .OrderBy(r => r.Name).ThenBy(r => r.Id).Page(slice).ToListAsync(ct), ct: ct);
}

public sealed class PostgresSessionRepository(Factory factory) : PostgresRepository(factory), ISessionRepository
{
    public Task AddAsync(Session x, string tokenHash, CancellationToken ct = default) => Run(async db =>
    {
        db.Sessions.Add(new SessionRow
        {
            Id = x.Id, UserId = x.UserId, AppId = x.AppId, CreatedAt = x.CreatedAt, LastUsedAt = x.LastUsedAt,
            ExpiresAt = x.ExpiresAt, RevokedAt = x.RevokedAt, TokenHash = tokenHash,
        });
        await db.SaveChangesAsync(ct);
        return 0;
    }, async (lookup, pg) =>
    {
        if (pg.SqlState != "23503") return null;
        if (!await lookup.Users.AnyAsync(u => u.Id == x.UserId)) return new NotFoundException($"User {x.UserId} not found.");
        return new NotFoundException($"Application {x.AppId} not found.");
    }, ct);

    public Task<Session?> GetAsync(Guid id, CancellationToken ct = default) => Run<Session?>(async db =>
        (await db.Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct))?.ToDomain(), ct: ct);

    public Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default) => Run<SessionHashes?>(async db =>
    {
        var row = await db.Sessions.AsNoTracking().Where(s => s.Id == id)
            .Select(s => new { s.TokenHash, s.PreviousTokenHash }).FirstOrDefaultAsync(ct);
        return row is null ? null : new SessionHashes(row.TokenHash, row.PreviousTokenHash);
    }, ct: ct);

    public Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid userId, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<Session>>(async db =>
        (await db.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.CreatedAt).ThenByDescending(s => s.Id).Page(slice).ToListAsync(ct))
        .Select(s => s.ToDomain()).ToList(), ct: ct);

    public Task<bool> RotateAsync(Guid id, string expectedHash, string newHash, DateTimeOffset now, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET previous_token_hash = token_hash, token_hash = {newHash}, last_used_at = {now} WHERE id = {id} AND token_hash = {expectedHash} AND revoked_at IS NULL AND expires_at > {now}", ct) > 0, ct: ct);

    public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = COALESCE(revoked_at, {now}) WHERE id = {id}", ct) > 0, ct: ct);

    public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) => Run(db =>
        db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = {now} WHERE user_id = {userId} AND revoked_at IS NULL AND expires_at > {now}", ct), ct: ct);

    public Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default) => Run(db =>
        db.Sessions.Where(s => s.ExpiresAt < expiredBefore).ExecuteDeleteAsync(ct), ct: ct);
}
