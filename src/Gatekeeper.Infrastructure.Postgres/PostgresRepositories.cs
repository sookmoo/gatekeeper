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
                case PostgresException pg: return pg.IsTransient; // connection class, shutdown, too many connections, ...
                case NpgsqlException: return true;                // could not connect, I/O failure
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

    public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<User>>(async db =>
    {
        var query = db.Users.AsNoTracking();
        if (active is not null) query = query.Where(u => u.IsActive == active);
        if (username is not null) query = query.Where(u => u.Username == username); // citext: case-insensitive
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
        var q = db.AuditEvents.AsNoTracking();
        if (actor is not null) q = q.Where(e => e.Actor == actor);
        if (action is not null) q = q.Where(e => e.Action == action);
        return await q.OrderByDescending(e => e.At).ThenByDescending(e => e.Id).Page(slice).ToListAsync(ct);
    }, ct: ct);
}
