using Gatekeeper.Application;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 7a: AddSessionCutoff is safe on a database that already holds users and sessions, works for the data-only role, gives up cleanly under a lock, and rolls back and forward.</summary>
public class Slice7aMigrationTests
{
    private const string Before = "20261023043512_AddVersions";

    private static async Task Exec(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<List<string>> Rows(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await using var r = await cmd.ExecuteReaderAsync();
        var list = new List<string>();
        while (await r.ReadAsync()) list.Add(r.IsDBNull(0) ? "<null>" : r.GetValue(0).ToString()!);
        return list;
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    private static async Task<(Guid App, Guid User, Guid S1, Guid S2)> Populate(string conn)
    {
        Guid app = Guid.NewGuid(), user = Guid.NewGuid(), s1 = Guid.NewGuid(), s2 = Guid.NewGuid();
        await Exec(conn,
            $"INSERT INTO apps (id, name) VALUES ('{app}', 'shop'); " +
            $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at) VALUES ('{user}', 'old', 'old@example.com', 'Old', true, now(), now()); " +
            $"INSERT INTO sessions (id, user_id, app_id, created_at, last_used_at, expires_at, token_hash) VALUES " +
            $"('{s1}', '{user}', '{app}', '2026-10-20 10:00:00.123456+00', '2026-10-21 10:00:00+00', now() + interval '30 days', 'h1'), " +
            $"('{s2}', '{user}', '{app}', '2026-10-22 11:30:00+00', '2026-10-22 11:30:00+00', now() + interval '30 days', 'h2')");
        return (app, user, s1, s2);
    }

    [SkippableFact]
    public async Task Existing_sessions_get_their_creation_time_as_the_sign_in_stamp_and_no_user_has_a_cut_off()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        var (_, user, s1, s2) = await Populate(conn);

        await MigrateTo(conn, null);

        Assert.Equal(["<null>"], await Rows(conn, "SELECT sessions_valid_after FROM users"));
        Assert.Equal(["timestamp with time zone|YES"], await Rows(conn,
            "SELECT data_type || '|' || is_nullable FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'sessions_valid_after'"));
        Assert.Equal(["timestamp with time zone|NO|<null>"], await Rows(conn,
            "SELECT data_type || '|' || is_nullable || '|' || coalesce(column_default, '<null>') FROM information_schema.columns WHERE table_name = 'sessions' AND column_name = 'authenticated_at'"));
        Assert.Equal(["0"], await Rows(conn, "SELECT count(*) FROM sessions WHERE authenticated_at <> created_at"));
        Assert.Equal(["2026-10-20T10:00:00.1234560+00:00"], await Rows(conn, $"SELECT to_char(authenticated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US0\"+00:00\"') FROM sessions WHERE id = '{s1}'"));
        // NULL is refused, and an insert from older code (without the column) fails loudly rather than creating a session the cut-off cannot judge
        var noStamp = await Assert.ThrowsAsync<PostgresException>(() => Exec(conn,
            $"INSERT INTO sessions (id, user_id, app_id, created_at, last_used_at, expires_at, token_hash) SELECT gen_random_uuid(), '{user}', app_id, now(), now(), now() + interval '1 day', 'x' FROM sessions LIMIT 1"));
        Assert.Equal("23502", noStamp.SqlState);

        // the data-only role reads, lists, rotates and revokes the old sessions through the stores (existing sessions all still count)
        db.GrantAppAccess();
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        var sessions = sp.GetRequiredService<ISessionRepository>();
        var users = sp.GetRequiredService<IUserRepository>();
        Assert.Null((await users.GetAsync(user))!.SessionsValidAfter);
        Assert.Equal([s2, s1], (await sessions.ListActiveByUserAsync(user, DateTimeOffset.UtcNow)).Select(x => x.Id));
        Assert.True(await sessions.RotateAsync(s1, "h1", "h1b", DateTimeOffset.UtcNow));
        Assert.Equal(2, await sessions.RevokeAllAndCutOffAsync(user, DateTimeOffset.UtcNow.AddMinutes(1)));
        Assert.NotNull((await users.GetAsync(user))!.SessionsValidAfter);
        await sp.GetRequiredService<ICredentialRepository>().SetAsync(user, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(2));

        // Down first ends the sessions the cut-off was ending (the older code cannot tell), and leaves the ones that still count alone
        await Exec(conn,
            $"UPDATE users SET sessions_valid_after = '2026-10-21 00:00:00+00' WHERE id = '{user}'; " +
            "UPDATE sessions SET revoked_at = NULL; " +
            $"UPDATE sessions SET authenticated_at = '2026-10-22 00:00:00+00' WHERE id = '{s2}'");
        // s1 (authenticated 2026-10-20) is cut off and not revoked; s2 (2026-10-22) still counts
        await MigrateTo(conn, Before);
        Assert.Equal(["revoked"], await Rows(conn, $"SELECT CASE WHEN revoked_at IS NULL THEN 'live' ELSE 'revoked' END FROM sessions WHERE id = '{s1}'"));
        Assert.Equal(["live"], await Rows(conn, $"SELECT CASE WHEN revoked_at IS NULL THEN 'live' ELSE 'revoked' END FROM sessions WHERE id = '{s2}'"));
        await MigrateTo(conn, null);
        await MigrateTo(conn, Before);
        Assert.Empty(await Rows(conn, "SELECT 1 FROM information_schema.columns WHERE (table_name = 'users' AND column_name = 'sessions_valid_after') OR (table_name = 'sessions' AND column_name = 'authenticated_at')"));
        Assert.Equal(["2"], await Rows(conn, "SELECT count(*) FROM sessions"));
        await MigrateTo(conn, null);
        Assert.Equal(["0"], await Rows(conn, "SELECT count(*) FROM sessions WHERE authenticated_at <> created_at"));
    }

    [SkippableFact]
    public async Task The_migration_gives_up_cleanly_when_a_long_query_holds_a_conflicting_lock_and_works_when_retried()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        await Populate(conn);

        await using (var holder = new NpgsqlConnection(conn))
        {
            await holder.OpenAsync();
            await using var tx = await holder.BeginTransactionAsync();
            await using (var read = new NpgsqlCommand("SELECT count(*) FROM sessions", holder, tx)) await read.ExecuteScalarAsync(); // ACCESS SHARE until commit
            var started = DateTime.UtcNow;
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => MigrateTo(conn, null));
            Assert.Contains("55P03", ex.ToString()); // lock_not_available, after about two seconds, not an unbounded wait
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(30));
        }
        // rolled back as a whole: nothing half-applied
        Assert.Empty(await Rows(conn, "SELECT 1 FROM information_schema.columns WHERE (table_name = 'users' AND column_name = 'sessions_valid_after') OR (table_name = 'sessions' AND column_name = 'authenticated_at')"));
        await MigrateTo(conn, null);
        Assert.Equal(["0"], await Rows(conn, "SELECT count(*) FROM sessions WHERE authenticated_at <> created_at"));
    }
}
