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
public abstract class PostgresRepository(Factory factory)
{
    private const string UniqueViolation = "23505";
    private const string ForeignKeyViolation = "23503";

    protected async Task<T> Run<T>(Func<GatekeeperDbContext, Task<T>> operation, Translator? translate = null)
    {
        try
        {
            await using var db = await factory.CreateDbContextAsync();
            try
            {
                return await operation(db);
            }
            catch (Exception ex) when (translate is not null && ConstraintViolation(ex) is { } pg)
            {
                // Translate on a fresh context: the failed one may hold tracked entities in a bad state.
                await using var lookup = await factory.CreateDbContextAsync();
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
    public Task<App> AddAsync(App app) => Run(async db =>
    {
        db.Apps.Add(app);
        await db.SaveChangesAsync();
        return app;
    }, Translate(app));

    public Task<App?> GetAsync(Guid id) =>
        Run(db => db.Apps.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id));

    public Task<IReadOnlyList<App>> ListAsync() =>
        Run<IReadOnlyList<App>>(async db => await db.Apps.AsNoTracking().OrderBy(a => a.Name).ToListAsync());

    public Task<App?> UpdateAsync(App app) => Run<App?>(async db =>
    {
        db.Apps.Update(app);
        try
        {
            await db.SaveChangesAsync();
            return app;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null; // row no longer exists
        }
    }, Translate(app));

    public Task<bool> DeleteAsync(Guid id) =>
        Run(async db => await db.Apps.Where(a => a.Id == id).ExecuteDeleteAsync() > 0);

    private static Translator Translate(App app) => (_, pg) => Task.FromResult<GatekeeperException?>(
        pg.ConstraintName == Names.AppNameIndex ? new ConflictException($"Application '{app.Name}' already exists.") : null);
}

public sealed class PostgresRoleRepository(Factory factory) : PostgresRepository(factory), IRoleRepository
{
    public Task<Role> AddAsync(Role role) => Run(async db =>
    {
        db.Roles.Add(role);
        await db.SaveChangesAsync();
        return role;
    }, Translate(role));

    public Task<Role?> GetAsync(Guid id) =>
        Run(db => db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id));

    public Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId) => Run<IReadOnlyList<Role>>(async db =>
        await db.Roles.AsNoTracking().Where(r => r.AppId == appId).OrderBy(r => r.Name).ToListAsync());

    public Task<Role?> UpdateAsync(Role role) => Run<Role?>(async db =>
    {
        db.Roles.Update(role);
        try
        {
            await db.SaveChangesAsync();
            return role;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null;
        }
    }, Translate(role));

    public Task<bool> DeleteAsync(Guid id) =>
        Run(async db => await db.Roles.Where(r => r.Id == id).ExecuteDeleteAsync() > 0);

    private static Translator Translate(Role role) => (_, pg) => Task.FromResult<GatekeeperException?>(pg.ConstraintName switch
    {
        Names.RoleNameIndex => new ConflictException($"Role '{role.Name}' already exists in this application."),
        Names.RoleAppFk => new NotFoundException($"Application {role.AppId} not found."),
        _ => null,
    });
}

public sealed class PostgresUserRepository(Factory factory) : PostgresRepository(factory), IUserRepository
{
    public Task<User> AddAsync(User user) => Run(async db =>
    {
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }, TranslateUnique(user));

    public Task<User?> GetAsync(Guid id) =>
        Run(db => db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id));

    public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null) => Run<IReadOnlyList<User>>(async db =>
    {
        var query = db.Users.AsNoTracking();
        if (active is not null) query = query.Where(u => u.IsActive == active);
        if (username is not null) query = query.Where(u => u.Username == username); // citext: case-insensitive
        return await query.OrderBy(u => u.Username).ToListAsync();
    });

    public Task<User?> UpdateAsync(User user) => Run<User?>(async db =>
    {
        db.Users.Update(user);
        try
        {
            await db.SaveChangesAsync();
            return user;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null;
        }
    }, TranslateUnique(user));

    public Task<bool> DeleteAsync(Guid id) =>
        Run(async db => await db.Users.Where(u => u.Id == id).ExecuteDeleteAsync() > 0);

    public Task AssignRoleAsync(Guid userId, Guid roleId) => Run(async db =>
    {
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO user_roles (user_id, role_id) VALUES ({userId}, {roleId}) ON CONFLICT DO NOTHING");
        return 0;
    }, async (lookup, pg) =>
    {
        if (pg.SqlState != "23503") return null;
        // When both are missing, report the user first (same precedence as the in-memory store).
        if (!await lookup.Users.AnyAsync(u => u.Id == userId)) return new NotFoundException($"User {userId} not found.");
        return new NotFoundException($"Role {roleId} not found.");
    });

    public Task<bool> RevokeRoleAsync(Guid userId, Guid roleId) => Run(async db =>
        await db.UserRoles.Where(x => x.UserId == userId && x.RoleId == roleId).ExecuteDeleteAsync() > 0);

    public Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null) => Run<IReadOnlyList<Role>>(async db =>
    {
        var query = db.UserRoles.AsNoTracking()
            .Where(x => x.UserId == userId)
            .Join(db.Roles, x => x.RoleId, r => r.Id, (_, r) => r);
        if (appId is not null) query = query.Where(r => r.AppId == appId);
        return await query.OrderBy(r => r.Name).ToListAsync();
    });

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
