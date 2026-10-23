using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 6c: AddAuditIndexes applies on a database that already holds audit rows, keeps them append-only, rolls back and forward.</summary>
public class Slice6cMigrationTests
{
    private const string Before = "20261015124853_AddUserKind";

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
        do { while (await r.ReadAsync()) list.Add(r.GetString(0)); } while (await r.NextResultAsync());
        return list;
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    [SkippableFact]
    public async Task The_indexes_are_added_to_a_database_with_audit_rows_which_stay_append_only_and_listable()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        await Exec(conn, "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES " +
            $"('{Guid.NewGuid()}', '2026-01-01 00:00:00+00', 'old', 'x', 'success'), ('{Guid.NewGuid()}', '2026-01-02 00:00:00+00', 'old', 'y', 'failure')");
        Assert.Empty(await Rows(conn, "SELECT indexname FROM pg_indexes WHERE tablename = 'audit_events' AND indexname IN ('ix_audit_events_actor_at_id','ix_audit_events_action_at_id')"));

        await MigrateTo(conn, null);
        var defs = await Rows(conn, "SELECT indexdef FROM pg_indexes WHERE tablename = 'audit_events' AND indexname LIKE 'ix_audit_events_a%_at_id' ORDER BY indexname");
        Assert.Equal(2, defs.Count);
        Assert.Contains(defs, d => d.Contains("(action, at DESC, id DESC)"));
        Assert.Contains(defs, d => d.Contains("(actor, at DESC, id DESC)"));
        Assert.Single(await Rows(conn, "SELECT indexname FROM pg_indexes WHERE indexname = 'ix_audit_events_at_id'"));

        // with plenty of rows the planner uses the filter index (seq scans discouraged: the table is tiny)
        await Exec(conn, "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), now() - (g || ' seconds')::interval, 'u' || (g % 50), 'a' || (g % 7), 'success' FROM generate_series(1, 2000) g; ANALYZE audit_events");
        var plan = string.Join("\n", await Rows(conn, "SET enable_seqscan = off; SET enable_bitmapscan = off; EXPLAIN SELECT * FROM audit_events WHERE actor = 'u3' AND (at, id) < (now(), gen_random_uuid()) ORDER BY at DESC, id DESC LIMIT 51"));
        Assert.Contains("ix_audit_events_actor_at_id", plan);

        // still append-only for the app role, and the repository lists with a cursor
        db.GrantAppAccess();
        await using (var app = new NpgsqlConnection(db.AppConnection))
        {
            await app.OpenAsync();
            foreach (var sql in new[] { "UPDATE audit_events SET actor = 'x'", "DELETE FROM audit_events", "TRUNCATE audit_events" })
            {
                await using var cmd = new NpgsqlCommand(sql, app);
                var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
                Assert.Equal("42501", ex.SqlState);
            }
        }
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        var audit = sp.GetRequiredService<IAuditRepository>();
        var old = await audit.ListAsync(actor: "old");
        Assert.Equal(["y", "x"], old.Select(e => e.Action));
        Assert.Equal(["x"], (await audit.ListAsync(actor: "old", after: new AuditKey(old[0].At, old[0].Id), take: 5)).Select(e => e.Action));

        await MigrateTo(conn, Before); // rolls back and forward again
        Assert.Empty(await Rows(conn, "SELECT indexname FROM pg_indexes WHERE indexname IN ('ix_audit_events_actor_at_id','ix_audit_events_action_at_id')"));
        await MigrateTo(conn, null);
        Assert.Equal(2, (await Rows(conn, "SELECT indexname FROM pg_indexes WHERE indexname IN ('ix_audit_events_actor_at_id','ix_audit_events_action_at_id')")).Count);
    }

    private const string AfterIndexes = "20261022160105_AddAuditIndexes";

    [SkippableFact]
    public async Task The_migration_keeps_valid_existing_indexes_and_replaces_an_invalid_one()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        // an operator pre-created one index (valid, same name); the other is an invalid leftover of an interrupted build
        await Exec(conn, "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), now(), 'u', 'a', 'success' FROM generate_series(1, 50)");
        await Exec(conn, "CREATE INDEX CONCURRENTLY ix_audit_events_actor_at_id ON audit_events (actor, at DESC, id DESC)");
        await Exec(conn, "CREATE INDEX CONCURRENTLY ix_audit_events_action_at_id ON audit_events (action)");
        await Exec(conn, "UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'ix_audit_events_action_at_id'::regclass");
        var keptOid = (await Rows(conn, "SELECT 'ix_audit_events_actor_at_id'::regclass::oid::text")).Single();

        await MigrateTo(conn, AfterIndexes);

        Assert.Equal(keptOid, (await Rows(conn, "SELECT 'ix_audit_events_actor_at_id'::regclass::oid::text")).Single()); // untouched
        Assert.Equal(["true"], await Rows(conn, "SELECT indisvalid::text FROM pg_index WHERE indexrelid = 'ix_audit_events_action_at_id'::regclass"));
        Assert.Contains("(action, at DESC, id DESC)", (await Rows(conn, "SELECT indexdef FROM pg_indexes WHERE indexname = 'ix_audit_events_action_at_id'")).Single());
        // the migration is repeatable
        await MigrateTo(conn, Before);
        await MigrateTo(conn, null);
        Assert.Equal(2, (await Rows(conn, "SELECT indexname FROM pg_indexes WHERE indexname IN ('ix_audit_events_actor_at_id','ix_audit_events_action_at_id')")).Count);
    }
}
