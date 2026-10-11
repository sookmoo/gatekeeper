using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Gatekeeper.Infrastructure.Postgres;

using Factory = IDbContextFactory<GatekeeperDbContext>;

internal static class Db
{
    private const string UniqueViolation = "23505";
    private const string ForeignKeyViolation = "23503";

    /// <summary>Runs a write and translates constraint violations into the port's domain exceptions.</summary>
    public static async Task<T> Write<T>(Func<Task<T>> action, Func<PostgresException, GatekeeperException?> translate)
    {
        try
        {
            return await action();
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pg
                                           && pg.SqlState is UniqueViolation or ForeignKeyViolation)
        {
            throw translate(pg) ?? throw new InvalidOperationException("Unmapped database constraint violation.", ex);
        }
        catch (PostgresException pg) when (pg.SqlState is UniqueViolation or ForeignKeyViolation)
        {
            throw translate(pg) ?? throw new InvalidOperationException("Unmapped database constraint violation.", pg);
        }
    }
}

public sealed class PostgresAppRepository(Factory factory) : IAppRepository
{
    public async Task<App> AddAsync(App app)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await Db.Write(async () =>
        {
            db.Apps.Add(app);
            await db.SaveChangesAsync();
            return app;
        }, Translate(app));
    }

    public async Task<App?> GetAsync(Guid id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Apps.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id);
    }

    public async Task<IReadOnlyList<App>> ListAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Apps.AsNoTracking().OrderBy(a => a.Name).ToListAsync();
    }

    public async Task<App?> UpdateAsync(App app)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await Db.Write(async () =>
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
    }

    public async Task<bool> DeleteAsync(Guid id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Apps.Where(a => a.Id == id).ExecuteDeleteAsync() > 0;
    }

    private static Func<PostgresException, GatekeeperException?> Translate(App app) => pg =>
        pg.ConstraintName == Names.AppNameIndex ? new ConflictException($"Application '{app.Name}' already exists.") : null;
}

public sealed class PostgresRoleRepository(Factory factory) : IRoleRepository
{
    public async Task<Role> AddAsync(Role role)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await Db.Write(async () =>
        {
            db.Roles.Add(role);
            await db.SaveChangesAsync();
            return role;
        }, Translate(role));
    }

    public async Task<Role?> GetAsync(Guid id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id);
    }

    public async Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Roles.AsNoTracking().Where(r => r.AppId == appId).OrderBy(r => r.Name).ToListAsync();
    }

    public async Task<Role?> UpdateAsync(Role role)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await Db.Write(async () =>
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
    }

    public async Task<bool> DeleteAsync(Guid id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Roles.Where(r => r.Id == id).ExecuteDeleteAsync() > 0;
    }

    private static Func<PostgresException, GatekeeperException?> Translate(Role role) => pg => pg.ConstraintName switch
    {
        Names.RoleNameIndex => new ConflictException($"Role '{role.Name}' already exists in this application."),
        Names.RoleAppFk => new NotFoundException($"Application {role.AppId} not found."),
        _ => null,
    };
}

public sealed class PostgresUserRepository(Factory factory) : IUserRepository
{
    public async Task<User> AddAsync(User user)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await Db.Write(async () =>
        {
            db.Users.Add(user);
            await db.SaveChangesAsync();
            return user;
        }, Translate(user));
    }

    public async Task<User?> GetAsync(Guid id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null)
    {
        await using var db = await factory.CreateDbContextAsync();
        var query = db.Users.AsNoTracking();
        if (active is not null) query = query.Where(u => u.IsActive == active);
        if (username is not null) query = query.Where(u => u.Username == username); // citext: case-insensitive
        return await query.OrderBy(u => u.Username).ToListAsync();
    }

    public async Task<User?> UpdateAsync(User user)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await Db.Write(async () =>
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
        }, Translate(user));
    }

    public async Task<bool> DeleteAsync(Guid id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Users.Where(u => u.Id == id).ExecuteDeleteAsync() > 0;
    }

    public async Task AssignRoleAsync(Guid userId, Guid roleId)
    {
        await using var db = await factory.CreateDbContextAsync();
        await Db.Write(async () =>
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT INTO user_roles (user_id, role_id) VALUES ({userId}, {roleId}) ON CONFLICT DO NOTHING");
            return 0;
        }, pg => pg.ConstraintName switch
        {
            Names.AssignmentUserFk => new NotFoundException($"User {userId} not found."),
            Names.AssignmentRoleFk => new NotFoundException($"Role {roleId} not found."),
            _ => null,
        });
    }

    public async Task<bool> RevokeRoleAsync(Guid userId, Guid roleId)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.UserRoles.Where(x => x.UserId == userId && x.RoleId == roleId).ExecuteDeleteAsync() > 0;
    }

    public async Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null)
    {
        await using var db = await factory.CreateDbContextAsync();
        var query = db.UserRoles.AsNoTracking()
            .Where(x => x.UserId == userId)
            .Join(db.Roles, x => x.RoleId, r => r.Id, (_, r) => r);
        if (appId is not null) query = query.Where(r => r.AppId == appId);
        return await query.OrderBy(r => r.Name).ToListAsync();
    }

    private static Func<PostgresException, GatekeeperException?> Translate(User user) => pg => pg.ConstraintName switch
    {
        Names.UsernameIndex => new ConflictException($"Username '{user.Username}' is already taken."),
        Names.EmailIndex => new ConflictException($"Email '{user.Email}' is already in use."),
        _ => null,
    };
}
