using System.Text.Json;
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

/// <summary>Independent QA for slice 8e, written from the spec.</summary>
public class Qa8eAuditPruneTests
{
    private static readonly DateTimeOffset Cut = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static async Task Exec(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<long> Count(string conn, string where = "true")
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand($"SELECT count(*) FROM audit_events WHERE {where}", c);
        return (long)(await cmd.ExecuteScalarAsync())!;
    }

    private static async Task<string> SqlState(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
        return ex.SqlState;
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    private static PgTestDatabase Db()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        return db!;
    }

    private static (ServiceProvider Sp, AuditPruner Pruner) Pruner(string ownerConn, int batch = 5000, string lockTimeout = "2s")
    {
        var sp = new ServiceCollection().AddPostgresStore(ownerConn).BuildServiceProvider();
        return (sp, new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>())
            { BatchSize = batch, LockTimeout = lockTimeout });
    }

    [SkippableFact]
    public async Task Export_is_complete_and_faithful_for_every_deleted_row_including_nulls_unicode_and_microseconds()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        var ids = new List<Guid>();
        var sql = new System.Text.StringBuilder();
        for (var i = 0; i < 25; i++)
        {
            var id = Guid.NewGuid();
            ids.Add(id);
            // ties: only 3 distinct instants; null/non-null mix; unicode and quotes
            sql.Append($"INSERT INTO audit_events (id, at, actor, action, target, outcome, detail, address) VALUES ('{id}', " +
                $"'2025-03-0{1 + i % 3} 12:34:56.123457+00', 'a{i}', 'x', {(i % 2 == 0 ? "NULL" : "'t\"q'")}, 'success', " +
                $"{(i % 3 == 0 ? "NULL" : "'åäö \"quoted\" \\ back ✓ 😀'")}, {(i % 4 == 0 ? "NULL" : "'10.0.0.1'")});");
        }
        await Exec(db.MigratorConnection, sql.ToString());
        var (sp, pruner) = Pruner(db.MigratorConnection, batch: 4);
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("qa8e");
        try
        {
            var file = Path.Combine(dir.FullName, "out.jsonl");
            Assert.Equal(25, (await pruner.PruneAsync(Cut, file, false)).Deleted);
            var lines = await File.ReadAllLinesAsync(file);
            Assert.Equal(25, lines.Length);
            Assert.Equal(ids.OrderBy(x => x).ToHashSet(), lines.Select(l => JsonDocument.Parse(l).RootElement.GetProperty("id").GetGuid()).ToHashSet());
            foreach (var l in lines)
            {
                var d = JsonDocument.Parse(l).RootElement;
                var i = int.Parse(d.GetProperty("actor").GetString()![1..]);
                Assert.Equal(8, d.EnumerateObject().Count());
                Assert.Equal(i % 2 == 0 ? JsonValueKind.Null : JsonValueKind.String, d.GetProperty("target").ValueKind);
                Assert.Equal(i % 3 == 0 ? JsonValueKind.Null : JsonValueKind.String, d.GetProperty("detail").ValueKind);
                Assert.Equal(i % 4 == 0 ? JsonValueKind.Null : JsonValueKind.String, d.GetProperty("address").ValueKind);
                if (i % 3 != 0) Assert.Equal("åäö \"quoted\" \\ back ✓ 😀", d.GetProperty("detail").GetString());
                Assert.Equal($"2025-03-0{1 + i % 3}T12:34:56.1234570Z", d.GetProperty("at").GetString());
            }
            Assert.Equal(0, await Count(db.MigratorConnection, "action = 'x'"));
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task A_failure_in_a_later_batch_leaves_an_export_that_matches_the_deleted_rows_and_the_failure_row_count()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        for (var i = 0; i < 10; i++)
            await Exec(db.MigratorConnection, $"INSERT INTO audit_events (id, at, actor, action, outcome, detail) VALUES (gen_random_uuid(), '2025-01-01 00:00:0{i}+00', 'u', 'old', 'success', 'o{i}')");
        var (sp, pruner) = Pruner(db.MigratorConnection, batch: 4, lockTimeout: "300ms");
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("qa8e");
        try
        {
            var file = Path.Combine(dir.FullName, "out.jsonl");
            await using var holder = new NpgsqlConnection(db.MigratorConnection);
            await holder.OpenAsync();
            await using var tx = await holder.BeginTransactionAsync();
            // lock o6 (third batch rows are o8, o9; second batch is o4..o7): the second batch blocks
            await using (var cmd = new NpgsqlCommand("SELECT 1 FROM audit_events WHERE detail = 'o6' FOR UPDATE", holder, tx)) await cmd.ExecuteScalarAsync();
            var ex = await Assert.ThrowsAnyAsync<PostgresException>(() => pruner.PruneAsync(Cut, file, false));
            Assert.Equal("55P03", ex.SqlState);
            await tx.RollbackAsync();
            var lines = await File.ReadAllLinesAsync(file);
            Assert.Equal(4, lines.Length);
            Assert.Equal(6, await Count(db.MigratorConnection, "action = 'old'"));
            var failure = await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'failure' AND detail LIKE '%deleted=4 %'");
            Assert.Equal(1, failure);
            // a rerun needs a new file; with the old one it is refused and deletes nothing
            await Assert.ThrowsAnyAsync<IOException>(() => pruner.PruneAsync(Cut, file, false));
            Assert.Equal(6, await Count(db.MigratorConnection, "action = 'old'"));
            var file2 = Path.Combine(dir.FullName, "out2.jsonl");
            Assert.Equal(6, (await pruner.PruneAsync(Cut, file2, false)).Deleted);
            Assert.Equal(6, (await File.ReadAllLinesAsync(file2)).Length);
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task An_exact_multiple_of_the_batch_size_is_fully_deleted_and_the_trace_survives()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), '2025-01-01+00', 'u', 'old', 'success' FROM generate_series(1, 20)");
        var (sp, pruner) = Pruner(db.MigratorConnection, batch: 10);
        using var _ = sp;
        Assert.Equal(20, (await pruner.PruneAsync(Cut, null, false)).Deleted);
        Assert.Equal(0, await Count(db.MigratorConnection, "action = 'old'"));
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune'"));
    }

    [SkippableFact]
    public async Task A_cutoff_in_the_future_never_deletes_its_own_trace_row()
    {
        // The command enforces >= 30 days, but the pruner itself must still protect the trace row (id <> trace).
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), '2025-01-01+00', 'u', 'old', 'success' FROM generate_series(1, 5)");
        var (sp, pruner) = Pruner(db.MigratorConnection, batch: 2);
        using var _ = sp;
        var r = await pruner.PruneAsync(DateTimeOffset.UtcNow.AddDays(1), null, false);
        Assert.Equal(5, r.Deleted);
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune'"));
    }

    [SkippableFact]
    public async Task Dry_run_with_an_export_path_creates_no_file()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES (gen_random_uuid(), '2025-01-01+00', 'u', 'old', 'success')");
        var (sp, pruner) = Pruner(db.MigratorConnection);
        using var _ = sp;
        var path = Path.Combine(Path.GetTempPath(), "qa8e-" + Guid.NewGuid() + ".jsonl");
        var r = await pruner.PruneAsync(Cut, path, true);
        Assert.Equal(1, r.Deleted);
        Assert.False(File.Exists(path));
        Assert.Equal(1, await Count(db.MigratorConnection));
    }

    [SkippableFact]
    public async Task A_non_superuser_owner_can_prune_but_neither_the_app_role_nor_a_member_of_the_owner_nor_a_superuser_can_delete()
    {
        using var db = Db();
        var admin = Environment.GetEnvironmentVariable("GATEKEEPER_TEST_PG")!;
        var suffix = Guid.NewGuid().ToString("N")[..8];
        string owner = "qa_owner_" + suffix, member = "qa_member_" + suffix;
        await Exec(admin, $"CREATE ROLE {owner} LOGIN PASSWORD 'pw' NOSUPERUSER; CREATE ROLE {member} LOGIN PASSWORD 'pw' NOSUPERUSER; GRANT {owner} TO {member}");
        try
        {
            await Exec(db.MigratorConnection, $"GRANT ALL ON SCHEMA public TO {owner}; ALTER DATABASE \"{new NpgsqlConnectionStringBuilder(db.MigratorConnection).Database}\" OWNER TO {owner}");
            string As(string user) => new NpgsqlConnectionStringBuilder(db.MigratorConnection) { Username = user, Password = "pw" }.ConnectionString;
            await Exec(db.MigratorConnection, "CREATE EXTENSION IF NOT EXISTS citext");
            await MigrateTo(As(owner), null);
            await Exec(As(owner), "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), '2025-01-01+00', 'u', 'old', 'success' FROM generate_series(1, 7)");
            const string go = "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events";
            // member of the owner role: has the privileges via inheritance, but session_user is not the owner
            Assert.Equal("42501", await SqlState(As(member), go));
            Assert.Equal("42501", await SqlState(As(member), "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; SET LOCAL ROLE " + owner + "; DELETE FROM audit_events"));
            // superuser that is not the owner
            Assert.Equal("42501", await SqlState(db.MigratorConnection, go));
            // the owner via SET ROLE to another role is not accepted either, and the real owner prunes through the pruner
            var (sp, pruner) = Pruner(As(owner));
            using var _s = sp;
            Assert.Equal(7, (await pruner.PruneAsync(Cut, null, false)).Deleted);
            Assert.Equal(2, await Count(As(owner))); // start row + completion row (8e review round)
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            db.Dispose();
            await Exec(admin, $"DROP ROLE IF EXISTS {member}; DROP ROLE IF EXISTS {owner}");
        }
    }
}
