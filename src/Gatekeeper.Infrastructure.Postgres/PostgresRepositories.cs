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

    private const int MaxUpdateAttempts = 20;
    private const string LockNotAvailable = "55P03";

    protected static bool IsLockTimeout(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
            if (ex is PostgresException { SqlState: LockNotAvailable }) return true;
        return false;
    }

    /// <summary>
    /// Versioned update of the row with this id: loads it, refuses with <see cref="PreconditionFailedException"/> if a version is
    /// expected and differs, applies <paramref name="change"/> (which gets the stored row and returns the new values) and writes it with
    /// version + 1. The write is <c>UPDATE ... WHERE id = @id AND version = @loaded</c> (the version is an EF concurrency token), so a
    /// competing write between the load and the save is detected and a conditional update then fails with 412.
    /// An unconditional update has no version to defend, so it takes a row lock (<c>SELECT ... FOR UPDATE</c> in a transaction): unconditional
    /// writers of one row queue up and each succeeds with its own version instead of failing under contention. Null when the row does not exist.
    /// </summary>
    /// <param name="sameTransaction">An extra statement that must commit or roll back with the update (it runs after the row is saved); a conditional update then also runs in a transaction.</param>
    protected static async Task<T?> UpdateVersionedAsync<T>(GatekeeperDbContext db, Guid id, long? expected, Func<T, T> change, CancellationToken ct,
        Func<T, Task>? sameTransaction = null)
        where T : class, IVersioned
    {
        var table = db.Model.FindEntityType(typeof(T))!.GetTableName()!;
        for (var attempt = 0; attempt < MaxUpdateAttempts; attempt++)
        {
            db.ChangeTracker.Clear();
            await using var tx = expected is null || sameTransaction is not null ? await db.Database.BeginTransactionAsync(ct) : null;
            // Bounded wait for the row lock: a stuck writer must not pin every other request behind it (503 + Retry-After instead).
            if (tx is not null) await db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '2s'", ct);
            T? row;
            try
            {
#pragma warning disable EF1002 // the table name comes from the EF model, never from input; the id is a parameter
                row = expected is null
                    ? (await db.Set<T>().FromSqlRaw($"SELECT * FROM \"{table}\" WHERE id = {{0}} FOR NO KEY UPDATE", id).ToListAsync(ct)).SingleOrDefault()
#pragma warning restore EF1002
                    : await db.Set<T>().Where(e => EF.Property<Guid>(e, "Id") == id).FirstOrDefaultAsync(ct);
            }
            catch (Exception ex) when (IsLockTimeout(ex))
            {
                throw new BusyException();
            }
            if (row is null) return null;
            if (expected is { } want && want != row.Version) throw new PreconditionFailedException();
            var loaded = row.Version;
            db.Entry(row).CurrentValues.SetValues(change(row)); // whatever version the new values carry is overwritten next
            db.Entry(row).Property("Version").CurrentValue = loaded + 1;
            try
            {
                await db.SaveChangesAsync(ct);
                if (sameTransaction is not null) await sameTransaction(row);
                if (tx is not null) await tx.CommitAsync(CancellationToken.None); // the row is written: do not abandon the commit half-way
                return row;
            }
            catch (Exception ex) when (tx is not null && IsLockTimeout(ex))
            {
                throw new BusyException();
            }
            catch (DbUpdateConcurrencyException)
            {
                // Only a conditional update (or a lock-free writer in between) gets here: look again.
            }
        }
        throw new StoreUnavailableException("The record is being changed by too many requests at once. Try again.");
    }

    /// <summary>
    /// Raises the user's session cut-off to at least <paramref name="to"/> (GREATEST ignores NULL, so a first cut-off is just stored). It never
    /// lowers it and does not touch the version: sessions are a separate resource from the user's own fields.
    /// </summary>
    protected static Task<int> RaiseCutOffAsync(GatekeeperDbContext db, Guid userId, DateTimeOffset to, CancellationToken ct) =>
        db.Database.ExecuteSqlInterpolatedAsync($"UPDATE users SET sessions_valid_after = GREATEST(sessions_valid_after, {to}) WHERE id = {userId}", ct);

    /// <summary>
    /// A password change's effect on sessions, inside the caller's transaction (see <see cref="ICredentialRepository"/>): lock the user row, raise the
    /// cut-off only if it really rises (<c>cut</c> greater than the stored one), re-stamp the kept session only then and only if it still counted under the
    /// old cut-off (never to an earlier stamp), and revoke every other active session of the user.
    /// </summary>
    protected static async Task EndSessionsAsync(GatekeeperDbContext db, Guid userId, DateTimeOffset cut, DateTimeOffset at, Guid? keep, CancellationToken ct)
    {
        var stored = await db.Database.SqlQuery<DateTimeOffset?>($"SELECT sessions_valid_after AS \"Value\" FROM users WHERE id = {userId} FOR NO KEY UPDATE").ToListAsync(ct);
        if (stored.Count == 0) return; // no such user
        var prev = stored[0];
        // Revoke first; the cut-off is the LAST write before the commit and is at least the clock now, so a sign-in stamped after the caller read its
        // clock but before this point is cut off too.
        if (keep is { } kept)
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE sessions SET revoked_at = {at} WHERE user_id = {userId} AND id <> {kept} AND revoked_at IS NULL AND expires_at > {at}", ct);
        else
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE sessions SET revoked_at = {at} WHERE user_id = {userId} AND revoked_at IS NULL AND expires_at > {at}", ct);
        var now = Clock.UtcNowMicros();
        if (now > cut) cut = now;
        if (prev is not { } p || cut > p)
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE users SET sessions_valid_after = {cut} WHERE id = {userId}", ct);
            if (keep is { } k)
            {
                var restamp = cut.AddTicks(10); // one microsecond after the cut-off: strictly later, so it alone survives
                if (prev is { } old)
                    await db.Database.ExecuteSqlInterpolatedAsync(
                        $"UPDATE sessions SET authenticated_at = GREATEST(authenticated_at, {restamp}) WHERE id = {k} AND user_id = {userId} AND revoked_at IS NULL AND expires_at > {at} AND authenticated_at > {old}", ct);
                else
                    await db.Database.ExecuteSqlInterpolatedAsync(
                        $"UPDATE sessions SET authenticated_at = GREATEST(authenticated_at, {restamp}) WHERE id = {k} AND user_id = {userId} AND revoked_at IS NULL AND expires_at > {at}", ct);
            }
        }
    }

    /// <summary>Runs the work in one transaction with a bounded wait for row locks (503 instead of a stuck request).</summary>
    protected static async Task<T> InTransactionAsync<T>(GatekeeperDbContext db, Func<Task<T>> work, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        try
        {
            await db.Database.ExecuteSqlRawAsync("SET LOCAL lock_timeout = '2s'", ct);
            var result = await work();
            await tx.CommitAsync(CancellationToken.None); // written: do not abandon the commit half-way
            return result;
        }
        catch (Exception ex) when (IsLockTimeout(ex))
        {
            throw new BusyException();
        }
    }

    /// <summary>Deletes the row; with an expected version only if it still has it. False when the row does not exist.</summary>
    protected static async Task<bool> DeleteVersionedAsync<T>(GatekeeperDbContext db, Guid id, long? expected, CancellationToken ct)
        where T : class, IVersioned
    {
        var rows = db.Set<T>().Where(e => EF.Property<Guid>(e, "Id") == id);
        if (expected is { } want) rows = rows.Where(e => EF.Property<long>(e, "Version") == want);
        if (await rows.ExecuteDeleteAsync(ct) > 0) return true;
        if (expected is not null && await db.Set<T>().AnyAsync(e => EF.Property<Guid>(e, "Id") == id, ct)) throw new PreconditionFailedException();
        return false;
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
        app = app with { Version = 1 };
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

    public Task<App?> UpdateAsync(App app, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => UpdateVersionedAsync<App>(db, app.Id, expectedVersion, _ => app, ct), Translate(app), ct);

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => DeleteVersionedAsync<App>(db, id, expectedVersion, ct), ct: ct);

    private static Translator Translate(App app) => (_, pg) => Task.FromResult<GatekeeperException?>(
        pg.ConstraintName == Names.AppNameIndex ? new ConflictException($"Application '{app.Name}' already exists.") : null);
}

public sealed class PostgresRoleRepository(Factory factory) : PostgresRepository(factory), IRoleRepository
{
    public Task<Role> AddAsync(Role role, CancellationToken ct = default) => Run(async db =>
    {
        role = role with { Version = 1 };
        db.Roles.Add(role);
        await db.SaveChangesAsync(ct);
        return role;
    }, Translate(role), ct);

    public Task<Role?> GetAsync(Guid id, CancellationToken ct = default) =>
        Run(db => db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct), ct: ct);

    public Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId, Slice? slice = null, CancellationToken ct = default) => Run<IReadOnlyList<Role>>(async db =>
        await db.Roles.AsNoTracking().Where(r => r.AppId == appId).OrderBy(r => r.Name).ThenBy(r => r.Id).Page(slice).ToListAsync(ct), ct: ct);

    public Task<Role?> UpdateAsync(Role role, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => UpdateVersionedAsync<Role>(db, role.Id, expectedVersion, _ => role, ct), Translate(role), ct);

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => DeleteVersionedAsync<Role>(db, id, expectedVersion, ct), ct: ct);

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
        user = user with { Version = 1 };
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

    public Task<User?> UpdateAsync(User user, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => UpdateVersionedAsync<User>(db, user.Id, expectedVersion,
            // The cut-off column is never part of this UPDATE (it keeps the stored value); a requested rise is a GREATEST statement in the
            // same transaction, so a rise made by someone else in between cannot be undone by a stale copy.
            stored => user with { SessionsValidAfter = stored.SessionsValidAfter }, ct,
            user.SessionsValidAfter is not { } rise ? null : async saved =>
            {
                // Only a real raise writes (the caller passes the value it read on every update; that is not a raise).
                if (saved.SessionsValidAfter is { } had && had >= rise) return;
                await RaiseCutOffAsync(db, user.Id, rise, ct);
                db.Entry(saved).Property(nameof(User.SessionsValidAfter)).CurrentValue = rise;
            }), TranslateUnique(user), ct);

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => DeleteVersionedAsync<User>(db, id, expectedVersion, ct), ct: ct);

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
    public Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default) => Run(async db =>
    {
        Task<int> Upsert() => db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO user_credentials (user_id, hash, updated_at) VALUES ({userId}, {hash}, {at}) ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash, updated_at = EXCLUDED.updated_at", ct);
        if (cutOffAt is not { } cut)
        {
            await Upsert();
            return 0;
        }
        // The new hash, the cut-off and the revoke of the sessions commit together, under the credential row lock (a sign-in inserting a session
        // under a share lock on this row either finishes first and is revoked here, or waits and then sees the new hash).
        return await InTransactionAsync(db, async () =>
        {
            var existed = (await db.Database.SqlQuery<int>($"SELECT 1 AS \"Value\" FROM user_credentials WHERE user_id = {userId} FOR UPDATE").ToListAsync(ct)).Count > 0;
            await Upsert();
            if (existed) await EndSessionsAsync(db, userId, cut, at, null, ct); // a first password has nothing to end
            return 0;
        }, ct);
    }, (_, pg) => Task.FromResult<GatekeeperException?>(
        pg.ConstraintName == Names.CredentialUserFk ? new NotFoundException($"User {userId} not found.") : null), ct);

    public Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default) => Run(async db =>
    {
        Task<int> Replace() => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE user_credentials SET hash = {newHash}, updated_at = {at} WHERE user_id = {userId} AND hash = {expectedHash}", ct);
        if (cutOffAt is not { } cut) return await Replace() > 0;
        // Hash, cut-off, re-stamp of the kept session and revoke of the others are one transaction (the compare-and-set decides all of it).
        return await InTransactionAsync(db, async () =>
        {
            if (await Replace() == 0) return false;
            await EndSessionsAsync(db, userId, cut, at, keepSession, ct);
            return true;
        }, ct);
    }, ct: ct);

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

    public Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, AuditKey? after = null, int? take = null, CancellationToken ct = default) => Run<IReadOnlyList<AuditEvent>>(async db =>
    {
        // Stored text never contains NUL or malformed Unicode (Postgres cannot even compare against it): nothing matches.
        if ((actor is not null && !Validation.IsCleanText(actor)) || (action is not null && !Validation.IsCleanText(action))) return [];
        // The keyset predicate is a row-value comparison in SQL: uuid compares as unsigned bytes, the order AuditKey.CompareIds
        // reproduces for the in-memory store (and the order of the (at, id) indexes). The rest composes on top as a subquery.
        IQueryable<AuditEvent> q = after is { } k
            ? db.AuditEvents.FromSql($"SELECT * FROM audit_events WHERE (at, id) < ({k.At.ToUniversalTime()}, {k.Id})")
            : db.AuditEvents;
        q = q.AsNoTracking();
        if (actor is not null) q = q.Where(e => e.Actor == actor);
        if (action is not null) q = q.Where(e => e.Action == action);
        q = q.OrderByDescending(e => e.At).ThenByDescending(e => e.Id);
        return await (take is { } n ? q.Take(n) : q).ToListAsync(ct);
    }, ct: ct);
}

public sealed class PostgresClientRepository(Factory factory) : PostgresRepository(factory), IClientRepository
{
    public Task<Client> AddAsync(Client client, string secretHash, CancellationToken ct = default) => Run(async db =>
    {
        client = client with { Version = 1 };
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

    public Task<Client?> UpdateAsync(Client client, long? expectedVersion = null, CancellationToken ct = default) => Run(
        // Only these columns may change: the application is fixed at creation.
        db => UpdateVersionedAsync<Client>(db, client.Id, expectedVersion,
            stored => stored with { Name = client.Name, IsActive = client.IsActive, UpdatedAt = client.UpdatedAt }, ct),
        (_, pg) => Task.FromResult<GatekeeperException?>(
            pg.ConstraintName == Names.ClientNameIndex ? new ConflictException($"Client '{client.Name}' already exists.") : null), ct);

    public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default) =>
        Run(db => DeleteVersionedAsync<Client>(db, id, expectedVersion, ct), ct: ct);

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
    private static SessionRow RowOf(Session x, string tokenHash) => new()
    {
        Id = x.Id, UserId = x.UserId, AppId = x.AppId, CreatedAt = x.CreatedAt, LastUsedAt = x.LastUsedAt,
        ExpiresAt = x.ExpiresAt, RevokedAt = x.RevokedAt, AuthenticatedAt = x.Stamp, TokenHash = tokenHash,
    };

    private static Translator TranslateAdd(Session x) => async (lookup, pg) =>
    {
        if (pg.SqlState != "23503") return null;
        if (!await lookup.Users.AnyAsync(u => u.Id == x.UserId)) return new NotFoundException($"User {x.UserId} not found.");
        return new NotFoundException($"Application {x.AppId} not found.");
    };

    public Task AddAsync(Session x, string tokenHash, CancellationToken ct = default) => Run(async db =>
    {
        db.Sessions.Add(RowOf(x, tokenHash));
        await db.SaveChangesAsync(ct);
        return 0;
    }, TranslateAdd(x), ct);

    public Task<bool> AddForCredentialAsync(Session x, string tokenHash, string credentialHash, CancellationToken ct = default) => Run(db => InTransactionAsync(db, async () =>
    {
        // FOR SHARE blocks a concurrent password change (its UPDATE needs FOR NO KEY UPDATE) until this insert commits, and waits for one in
        // progress, after which the row no longer matches and nothing is inserted.
        var current = (await db.Database.SqlQuery<int>(
            $"SELECT 1 AS \"Value\" FROM user_credentials WHERE user_id = {x.UserId} AND hash = {credentialHash} FOR SHARE").ToListAsync(ct)).Count > 0;
        if (!current) return false;
        db.Sessions.Add(RowOf(x, tokenHash));
        await db.SaveChangesAsync(ct);
        return true;
    }, ct), TranslateAdd(x), ct);

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
            .Where(s => !db.Users.Any(u => u.Id == s.UserId && u.SessionsValidAfter != null && s.AuthenticatedAt <= u.SessionsValidAfter))
            .OrderByDescending(s => s.CreatedAt).ThenByDescending(s => s.Id).Page(slice).ToListAsync(ct))
        .Select(s => s.ToDomain()).ToList(), ct: ct);

    public Task<bool> RotateAsync(Guid id, string expectedHash, string newHash, DateTimeOffset now, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"""
            UPDATE sessions SET previous_token_hash = token_hash, token_hash = {newHash}, last_used_at = {now}
            WHERE id = {id} AND token_hash = {expectedHash} AND revoked_at IS NULL AND expires_at > {now}
              AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = sessions.user_id AND u.sessions_valid_after IS NOT NULL AND sessions.authenticated_at <= u.sessions_valid_after)
            """, ct) > 0, ct: ct);

    public Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = COALESCE(revoked_at, {now}) WHERE id = {id}", ct) > 0, ct: ct);

    public Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default) => Run(async db =>
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = COALESCE(revoked_at, {now}) WHERE id = {sessionId} AND user_id = {userId}", ct) > 0, ct: ct);

    public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) => Run(db =>
        db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = {now} WHERE user_id = {userId} AND revoked_at IS NULL AND expires_at > {now}", ct), ct: ct);

    public Task<int> RevokeAllAndCutOffAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default) => Run(db => InTransactionAsync(db, async () =>
    {
        if (await RaiseCutOffAsync(db, userId, now, ct) == 0) return 0; // no such user
        return await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = {now} WHERE user_id = {userId} AND revoked_at IS NULL AND expires_at > {now}", ct);
    }, ct), ct: ct);

    public Task<int> RevokeAllForUserExceptAsync(Guid userId, Guid keep, DateTimeOffset now, CancellationToken ct = default) => Run(db =>
        db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = {now} WHERE user_id = {userId} AND id <> {keep} AND revoked_at IS NULL AND expires_at > {now}", ct), ct: ct);

    public Task<int> RevokeAllForUserInAppAsync(Guid userId, Guid appId, DateTimeOffset now, CancellationToken ct = default) => Run(db =>
        db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET revoked_at = {now} WHERE user_id = {userId} AND app_id = {appId} AND revoked_at IS NULL AND expires_at > {now}", ct), ct: ct);

    public Task<int> CapExpiryForUserAsync(Guid userId, DateTimeOffset endsAt, DateTimeOffset now, CancellationToken ct = default) => Run(db =>
        db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE sessions SET expires_at = {endsAt} WHERE user_id = {userId} AND revoked_at IS NULL AND expires_at > {now} AND expires_at > {endsAt}", ct), ct: ct);

    public Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default) => Run(db =>
        db.Sessions.Where(s => s.ExpiresAt < expiredBefore).ExecuteDeleteAsync(ct), ct: ct);
}
