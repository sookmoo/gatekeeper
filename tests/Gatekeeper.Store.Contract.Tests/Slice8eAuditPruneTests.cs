using System.Diagnostics;
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

/// <summary>Slice 8e: the audit trigger exception for the owner, and the batched prune.</summary>
public class Slice8eAuditPruneTests
{
    private const string Before = "20261025213103_AddVersionTriggers";
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

    private static async Task<long> Scalar(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return (long)(await cmd.ExecuteScalarAsync())!;
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    private static async Task<string> SqlState(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
        return ex.SqlState;
    }

    private static PgTestDatabase Db()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        return db!;
    }

    private static async Task<(ServiceProvider Sp, AuditPruner Pruner)> Pruner(string ownerConn, int batch = 5000)
    {
        var sp = new ServiceCollection().AddPostgresStore(ownerConn).BuildServiceProvider();
        return (sp, new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>()) { BatchSize = batch });
    }

    private static Task Seed(string conn, int old, int recent, string at = "2025-06-01 00:00:00+00") => Exec(conn,
        $"INSERT INTO audit_events (id, at, actor, action, outcome, detail) SELECT gen_random_uuid(), '{at}'::timestamptz, 'u', 'old', 'success', 'o' || g FROM generate_series(1, {old}) g; " +
        $"INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), '2200-01-01 00:00:00+00'::timestamptz + (g || ' seconds')::interval, 'u', 'new', 'success' FROM generate_series(1, {recent}) g");

    [SkippableFact]
    public async Task The_app_role_gains_nothing_even_with_the_setting_and_a_granted_privilege()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        db.GrantAppAccess();
        await Seed(db.MigratorConnection, 3, 0);
        // The strongest attack: the privilege is granted (a mistake or a compromised owner) and the setting is on. The trigger still refuses.
        await Exec(db.MigratorConnection, "GRANT DELETE, UPDATE, TRUNCATE ON audit_events TO gk_test_app");
        foreach (var sql in new[] { "DELETE FROM audit_events", "UPDATE audit_events SET actor = 'x'", "TRUNCATE audit_events" })
        {
            Assert.Equal("42501", await SqlState(db.AppConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; " + sql));
            Assert.Equal("42501", await SqlState(db.AppConnection, sql));
        }
        await Exec(db.MigratorConnection, "REVOKE DELETE, UPDATE, TRUNCATE ON audit_events FROM gk_test_app");
        Assert.Equal("42501", await SqlState(db.AppConnection, "DELETE FROM audit_events")); // no privilege at all
        // Not via SET ROLE or a function either: the app role is not a member of the owner.
        Assert.NotEqual("00000", await SqlState(db.AppConnection, "SET ROLE postgres"));
        Assert.Equal(3, await Count(db.MigratorConnection));
    }

    [SkippableFact]
    public async Task The_owner_is_refused_without_the_setting_or_with_another_value_and_update_and_truncate_stay_refused()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        var owner = db.MigratorConnection;
        Assert.Equal("42501", await SqlState(owner, "DELETE FROM audit_events"));
        Assert.Equal("42501", await SqlState(owner, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'off'; DELETE FROM audit_events"));
        Assert.Equal("42501", await SqlState(owner, "BEGIN; SET LOCAL gatekeeper.audit_prune = ''; DELETE FROM audit_events"));
        Assert.Equal("42501", await SqlState(owner, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; UPDATE audit_events SET actor = 'x'"));
        Assert.Equal("42501", await SqlState(owner, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; TRUNCATE audit_events"));
        // The setting is transaction-local: after the transaction a plain delete is refused again.
        await Exec(owner, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events WHERE action = 'none'; COMMIT");
        Assert.Equal("42501", await SqlState(owner, "DELETE FROM audit_events"));
        Assert.Equal(3, await Count(owner));
    }

    [SkippableFact]
    public async Task The_owner_with_the_setting_can_delete()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        await Exec(db.MigratorConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events WHERE actor = 'u' AND detail = 'o1'; COMMIT");
        Assert.Equal(2, await Count(db.MigratorConnection));
    }

    [SkippableFact]
    public async Task Prune_deletes_only_rows_older_than_the_cutoff_in_batches_and_leaves_one_trace_row()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 23, 4);
        var (sp, pruner) = await Pruner(db.MigratorConnection, batch: 5);
        using var _ = sp;
        var result = await pruner.PruneAsync(Cut, null, false);
        Assert.Equal(23, result.Deleted);
        Assert.Equal(0, await Count(db.MigratorConnection, "action = 'old'"));
        Assert.Equal(4, await Count(db.MigratorConnection, "action = 'new'"));
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune'"));
        var trace = (await sp.GetRequiredService<IAuditRepository>().ListAsync(action: "audit.prune")).Single();
        Assert.Equal("system:prune", trace.Actor);
        Assert.Equal(AuditEvent.Success, trace.Outcome);
        Assert.Equal("before=2026-01-01T00:00:00Z deleted=23 exported=none", trace.Detail);
        // a second run finds nothing (the trace row is newer than the cut-off) and leaves a second trace
        Assert.Equal(0, (await pruner.PruneAsync(Cut, null, false)).Deleted);
        Assert.Equal(2, await Count(db.MigratorConnection, "action = 'audit.prune'"));
    }

    [SkippableFact]
    public async Task Many_rows_in_one_microsecond_are_all_deleted_across_batch_boundaries()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 53, 0);
        var (sp, pruner) = await Pruner(db.MigratorConnection, batch: 10); // same `at` for all 53; the batch boundary falls inside the tie
        using var _ = sp;
        Assert.Equal(53, (await pruner.PruneAsync(Cut, null, false)).Deleted);
        Assert.Equal(0, await Count(db.MigratorConnection, "action = 'old'"));
    }

    [SkippableFact]
    public async Task A_row_exactly_at_the_cutoff_is_kept_and_one_microsecond_earlier_is_deleted()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES " +
            $"('{Guid.NewGuid()}', '2026-01-01 00:00:00+00', 'u', 'edge', 'success'), ('{Guid.NewGuid()}', '2025-12-31 23:59:59.999999+00', 'u', 'edge-1', 'success')");
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        Assert.Equal(1, (await pruner.PruneAsync(Cut, null, false)).Deleted);
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'edge'"));
    }

    [SkippableFact]
    public async Task Dry_run_deletes_and_records_nothing_and_reports_the_count()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 7, 2);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        var result = await pruner.PruneAsync(Cut, null, true);
        Assert.True(result.DryRun);
        Assert.Equal(7, result.Deleted);
        Assert.Equal(9, await Count(db.MigratorConnection));
    }

    [SkippableFact]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public async Task Export_writes_every_deleted_row_as_json_lines_with_mode_0600_and_refuses_an_existing_file()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 12, 1);
        var (sp, pruner) = await Pruner(db.MigratorConnection, batch: 5);
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            var file = Path.Combine(dir.FullName, "audit.jsonl");
            var result = await pruner.PruneAsync(Cut, file, false);
            Assert.Equal(12, result.Deleted);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
            var lines = await File.ReadAllLinesAsync(file);
            Assert.Equal(12, lines.Length);
            var docs = lines.Select(l => JsonDocument.Parse(l).RootElement).ToList();
            Assert.All(docs, d => { Assert.Equal("old", d.GetProperty("action").GetString()); Assert.Equal("u", d.GetProperty("actor").GetString()); Assert.Equal("success", d.GetProperty("outcome").GetString()); });
            Assert.Equal(12, docs.Select(d => d.GetProperty("id").GetGuid()).Distinct().Count());
            Assert.StartsWith("2025-06-01T00:00:00", docs[0].GetProperty("at").GetString());
            Assert.Contains($"exported={JsonSerializer.Serialize(file)}", (await sp.GetRequiredService<IAuditRepository>().ListAsync(action: "audit.prune")).Single().Detail);

            // existing file (also a symlink): refused before anything is recorded or deleted
            await Seed(db.MigratorConnection, 2, 0);
            await Assert.ThrowsAsync<IOException>(() => pruner.PruneAsync(Cut, file, false));
            var link = Path.Combine(dir.FullName, "link");
            File.CreateSymbolicLink(link, Path.Combine(dir.FullName, "elsewhere"));
            await Assert.ThrowsAnyAsync<IOException>(() => pruner.PruneAsync(Cut, link, false));
            Assert.False(File.Exists(Path.Combine(dir.FullName, "elsewhere")));
            Assert.Equal(2, await Count(db.MigratorConnection, "action = 'old'"));
            Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune'"));
            Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune.start'")); // the refused runs recorded nothing
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task An_unusable_export_path_stops_the_run_before_anything_is_recorded_or_deleted()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => pruner.PruneAsync(Cut, dir.FullName, false)); // a directory
            await Assert.ThrowsAnyAsync<Exception>(() => pruner.PruneAsync(Cut, Path.Combine(dir.FullName, "missing", "x.jsonl"), false));
            Assert.Equal(3, await Count(db.MigratorConnection, "action = 'old'"));
            Assert.Equal(0, await Count(db.MigratorConnection, "action LIKE 'audit.prune%'"));
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task Audit_writes_are_not_blocked_while_a_prune_runs()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        db.GrantAppAccess();
        await Seed(db.MigratorConnection, 20000, 0);
        var (sp, pruner) = await Pruner(db.MigratorConnection, batch: 500);
        using var _ = sp;
        var prune = Task.Run(() => pruner.PruneAsync(Cut, null, false));
        var worst = TimeSpan.Zero;
        var written = 0;
        while (!prune.IsCompleted)
        {
            var sw = Stopwatch.StartNew();
            await Exec(db.AppConnection, $"INSERT INTO audit_events (id, at, actor, action, outcome) VALUES ('{Guid.NewGuid()}', now(), 'w', 'concurrent', 'success')");
            if (sw.Elapsed > worst) worst = sw.Elapsed;
            written++;
        }
        Assert.Equal(20000, (await prune).Deleted);
        Assert.True(worst < TimeSpan.FromSeconds(2), $"an audit insert waited {worst}");
        Assert.Equal(written, await Count(db.MigratorConnection, "action = 'concurrent'"));
    }

    [SkippableFact]
    public async Task The_lock_timeout_stops_a_batch_that_waits_on_a_row_lock_and_records_a_failure_row()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        pruner = new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>()) { LockTimeout = "300ms" };
        await using var holder = new NpgsqlConnection(db.MigratorConnection);
        await holder.OpenAsync();
        await using (var tx = await holder.BeginTransactionAsync())
        {
            await using (var cmd = new NpgsqlCommand("SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events WHERE detail = 'o1'", holder, tx))
                await cmd.ExecuteNonQueryAsync();
            var ex = await Assert.ThrowsAnyAsync<PostgresException>(() => pruner.PruneAsync(Cut, null, false));
            Assert.Equal("55P03", ex.SqlState);
            await tx.RollbackAsync();
        }
        Assert.Equal(3, await Count(db.MigratorConnection, "action = 'old'"));
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'failure'"));
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune.start' AND detail LIKE '%planned=3 %'"));
        Assert.Equal(0, await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'success'")); // no completion row for a failed run
    }

    [SkippableFact]
    public async Task The_migration_rolls_down_to_the_strict_trigger_and_up_again()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, Before);
        await Seed(db.MigratorConnection, 2, 0);
        Assert.Equal("42501", await SqlState(db.MigratorConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events"));
        await MigrateTo(db.MigratorConnection, null); // up
        await Exec(db.MigratorConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events WHERE detail = 'o1'; COMMIT");
        Assert.Equal(1, await Count(db.MigratorConnection));
        await MigrateTo(db.MigratorConnection, Before); // down
                Assert.Equal(0L, await Scalar(db.MigratorConnection, "SELECT count(*) FROM pg_trigger WHERE tgname = 'audit_events_guard_prune_rows'"));
        Assert.Equal("42501", await SqlState(db.MigratorConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events"));
        Assert.Equal("42501", await SqlState(db.MigratorConnection, "TRUNCATE audit_events"));
        Assert.Equal(1, await Count(db.MigratorConnection));
        await MigrateTo(db.MigratorConnection, null); // and up again
    }

    [SkippableFact]
    public async Task A_run_leaves_a_start_row_and_a_completion_row_stamped_with_database_time()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 1);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        await pruner.PruneAsync(Cut, null, false);
        var audit = sp.GetRequiredService<IAuditRepository>();
        var start = (await audit.ListAsync(action: "audit.prune.start")).Single();
        var done = (await audit.ListAsync(action: "audit.prune")).Single();
        Assert.Equal("before=2026-01-01T00:00:00Z planned=3 exported=none", start.Detail);
        Assert.Equal("before=2026-01-01T00:00:00Z deleted=3 exported=none", done.Detail);
        Assert.InRange((start.At - DateTimeOffset.UtcNow).Duration(), TimeSpan.Zero, TimeSpan.FromMinutes(1));
        Assert.True(start.At <= done.At);
    }

    [SkippableFact]
    public async Task A_cancelled_run_leaves_a_start_row_and_a_failure_row_with_the_real_count()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        for (var i = 0; i < 6; i++)
            await Exec(db.MigratorConnection, $"INSERT INTO audit_events (id, at, actor, action, outcome, detail) VALUES (gen_random_uuid(), '2025-01-01 00:00:0{i}+00', 'u', 'old', 'success', 'o{i}')");
        var (sp, pruner) = await Pruner(db.MigratorConnection, batch: 3);
        using var _ = sp;
        pruner = new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>()) { BatchSize = 3, LockTimeout = "30s" };
        await using var holder = new NpgsqlConnection(db.MigratorConnection);
        await holder.OpenAsync();
        await using var tx = await holder.BeginTransactionAsync();
        await using (var cmd = new NpgsqlCommand("SELECT 1 FROM audit_events WHERE detail = 'o4' FOR UPDATE", holder, tx)) await cmd.ExecuteScalarAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pruner.PruneAsync(Cut, null, false, cts.Token));
        await tx.RollbackAsync();
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune.start'"));
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'failure' AND detail LIKE '%deleted=3 %'"));
        Assert.Equal(3, await Count(db.MigratorConnection, "action = 'old'"));
    }

    [SkippableFact]
    public async Task An_empty_export_file_is_removed_when_the_run_fails_before_writing()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        var (sp, _) = await Pruner(db.MigratorConnection);
        using var __ = sp;
        var pruner = new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>()) { LockTimeout = "300ms" };
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            var file = Path.Combine(dir.FullName, "x.jsonl");
            await using var holder = new NpgsqlConnection(db.MigratorConnection);
            await holder.OpenAsync();
            await using var tx = await holder.BeginTransactionAsync();
            await using (var cmd = new NpgsqlCommand("SELECT 1 FROM audit_events WHERE detail = 'o1' FOR UPDATE", holder, tx)) await cmd.ExecuteScalarAsync();
            await Assert.ThrowsAnyAsync<PostgresException>(() => pruner.PruneAsync(Cut, file, false));
            await tx.RollbackAsync();
            Assert.False(File.Exists(file));
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task A_clock_difference_over_five_minutes_refuses_the_run_before_anything_is_written()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        using var sp = new ServiceCollection().AddPostgresStore(db.MigratorConnection).BuildServiceProvider();
        foreach (var offset in new[] { TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(-10) })
        {
            var pruner = new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>()) { Clock = new Skewed(offset) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneAsync(Cut, null, false));
            Assert.Contains("clock", ex.Message);
            await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneOlderThanAsync(30, null, false, false));
        }
        Assert.Equal(3, await Count(db.MigratorConnection));
        var ok = new AuditPruner(sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>(), sp.GetRequiredService<IAuditRepository>()) { Clock = new Skewed(TimeSpan.FromMinutes(4)) };
        Assert.Equal(3, (await ok.PruneAsync(Cut, null, false)).Deleted);
    }

    private sealed class Skewed(TimeSpan offset) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + offset;
    }

    [SkippableFact]
    public async Task The_command_entry_uses_the_database_clock_and_refuses_to_delete_almost_everything_without_allow_large()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        // 10 old of 11: over 90%
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), '2025-01-01+00', 'u', 'old', 'success' FROM generate_series(1, 10); " +
            "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES (gen_random_uuid(), now(), 'u', 'new', 'success')");
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneOlderThanAsync(30, null, false, false));
        Assert.Contains("--allow-large", ex.Message);
        Assert.Equal(11, await Count(db.MigratorConnection));
        var dry = await pruner.PruneOlderThanAsync(30, null, true, false);
        Assert.True(dry.DryRun);
        Assert.Equal((10, 11), (dry.Deleted, dry.Total));
        Assert.Equal(10, (await pruner.PruneOlderThanAsync(30, null, false, true)).Deleted);
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'new'"));
    }

    [SkippableFact]
    public async Task Half_of_the_table_is_below_the_guard_and_runs_without_allow_large()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), '2025-01-01+00', 'u', 'old', 'success' FROM generate_series(1, 5); " +
            "INSERT INTO audit_events (id, at, actor, action, outcome) SELECT gen_random_uuid(), now(), 'u', 'new', 'success' FROM generate_series(1, 5)");
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        Assert.Equal(5, (await pruner.PruneOlderThanAsync(30, null, false, false)).Deleted);
        // Everything older is already gone: nothing planned is not "large"
        Assert.Equal(0, (await pruner.PruneOlderThanAsync(30, null, false, false)).Deleted);
    }

    [SkippableFact]
    public async Task Earlier_prune_rows_are_never_deleted_by_a_prune_and_the_trigger_refuses_it_even_for_the_owner_with_the_setting()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome, detail) VALUES " +
            $"('{Guid.NewGuid()}', '2020-01-01+00', 'system:prune', 'audit.prune', 'success', 'ancient'), ('{Guid.NewGuid()}', '2020-01-02+00', 'system:prune', 'audit.prune.start', 'success', 'ancient start')");
        await Seed(db.MigratorConnection, 3, 0);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        Assert.Equal(3, (await pruner.PruneAsync(Cut, null, false)).Deleted);
        Assert.Equal(2, await Count(db.MigratorConnection, "detail LIKE 'ancient%'"));
        Assert.Equal("42501", await SqlState(db.MigratorConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events WHERE detail = 'ancient'"));
        Assert.Equal("42501", await SqlState(db.MigratorConnection, "BEGIN; SET LOCAL gatekeeper.audit_prune = 'on'; DELETE FROM audit_events WHERE actor = 'system:prune'"));
    }

    [Theory]
    [InlineData("2s; DROP TABLE audit_events")]
    [InlineData("")]
    [InlineData("-1s")]
    [InlineData("2 s")]
    [InlineData("1min")]
    [InlineData("2s\n")]
    public void The_lock_timeout_must_be_digits_and_ms_or_s(string value)
        => Assert.Throws<ArgumentException>(() => new AuditPruner(null!, null!) { LockTimeout = value });

    [Fact]
    public void A_valid_lock_timeout_is_accepted()
        => Assert.Equal("300ms", new AuditPruner(null!, null!) { LockTimeout = "300ms" }.LockTimeout);

    [SkippableFact]
    public async Task A_failed_commit_cuts_the_export_back_so_it_never_lists_rows_the_table_still_has()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        for (var i = 0; i < 6; i++)
            await Exec(db.MigratorConnection, $"INSERT INTO audit_events (id, at, actor, action, outcome, detail) VALUES (gen_random_uuid(), '2025-01-01 00:00:0{i}+00', 'u', 'old', 'success', 'o{i}')");
        // A deferred constraint trigger fails at COMMIT time for the second batch (rows o3..o5).
        await Exec(db.MigratorConnection,
            "CREATE FUNCTION gk_fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.detail = 'o4' THEN RAISE EXCEPTION 'no commit' USING ERRCODE = 'P0001'; END IF; RETURN OLD; END $$; " +
            "CREATE CONSTRAINT TRIGGER gk_fail_commit AFTER DELETE ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gk_fail_commit()");
        var (sp, pruner) = await Pruner(db.MigratorConnection, batch: 3);
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            var file = Path.Combine(dir.FullName, "x.jsonl");
            await Assert.ThrowsAnyAsync<PostgresException>(() => pruner.PruneAsync(Cut, file, false));
            var lines = await File.ReadAllLinesAsync(file);
            Assert.Equal(3, lines.Length); // only the committed first batch
            Assert.Equal("o0,o1,o2", string.Join(",", lines.Select(l => JsonDocument.Parse(l).RootElement.GetProperty("detail").GetString())));
            Assert.Equal(3, await Count(db.MigratorConnection, "action = 'old'"));
            Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'failure' AND detail LIKE '%deleted=3 %'"));
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task A_completion_row_that_cannot_be_written_leaves_a_failure_row_with_the_real_count_and_the_error_surfaces()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 4, 0);
        await Exec(db.MigratorConnection,
            "CREATE FUNCTION gk_fail_done() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no completion' USING ERRCODE = 'P0001'; END $$; " +
            "CREATE TRIGGER gk_fail_done BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action = 'audit.prune' AND NEW.outcome = 'success') EXECUTE FUNCTION gk_fail_done()");
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        await Assert.ThrowsAnyAsync<Exception>(() => pruner.PruneAsync(Cut, null, false));
        Assert.Equal(0, await Count(db.MigratorConnection, "action = 'old'"));
        Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'failure' AND detail LIKE '%deleted=4 %'"));
    }

    [SkippableFact]
    public async Task A_successful_run_that_deleted_nothing_removes_its_empty_export_file()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 0, 2);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            var file = Path.Combine(dir.FullName, "x.jsonl");
            Assert.Equal(0, (await pruner.PruneAsync(Cut, file, false)).Deleted);
            Assert.False(File.Exists(file));
            Assert.Equal(1, await Count(db.MigratorConnection, "action = 'audit.prune' AND outcome = 'success'"));
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public async Task Export_dir_creates_a_file_named_by_the_database_time_with_mode_0600_and_refuses_a_missing_directory()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            await Assert.ThrowsAsync<DirectoryNotFoundException>(() => pruner.PruneOlderThanAsync(30, null, false, true, exportDir: Path.Combine(dir.FullName, "missing")));
            var result = await pruner.PruneOlderThanAsync(30, null, false, true, exportDir: dir.FullName);
            var file = Assert.Single(Directory.GetFiles(dir.FullName));
            Assert.Matches(@"^audit-\d{8}T\d{6}Z\.jsonl$", Path.GetFileName(file));
            Assert.Equal(file, result.ExportFile);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
            Assert.Equal(3, (await File.ReadAllLinesAsync(file)).Length);
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task Every_trace_row_fits_the_audit_field_limit_with_the_longest_export_path()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        var root = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            // a file path of exactly MaxExportPath characters
            var name = "/x.jsonl";
            var dir = root.FullName + "/" + new string('d', AuditPruner.MaxExportPath - root.FullName.Length - 1 - name.Length);
            Directory.CreateDirectory(dir);
            var file = dir + name;
            Assert.Equal(AuditPruner.MaxExportPath, file.Length);
            Assert.Null(AuditPruner.CheckExportPathShape(file));
            await Exec(db.MigratorConnection, "CREATE FUNCTION gk_fail_done() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'x' USING ERRCODE = 'P0001'; END $$; " +
                "CREATE TRIGGER gk_fail_done BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action = 'audit.prune' AND NEW.outcome = 'success') EXECUTE FUNCTION gk_fail_done()");
            var (sp, pruner) = await Pruner(db.MigratorConnection);
            using var _ = sp;
            await Assert.ThrowsAnyAsync<Exception>(() => pruner.PruneAsync(Cut, file, false)); // start row + failure row (longest exception name is shorter than the one used here)
            await using var c = new NpgsqlConnection(db.MigratorConnection);
            await c.OpenAsync();
            await using var cmd = new NpgsqlCommand("SELECT max(length(detail)) FROM audit_events WHERE actor = 'system:prune'", c);
            var longest = (int)(await cmd.ExecuteScalarAsync())!;
            Assert.InRange(longest, 1, AuditEvent.MaxField - 15); // headroom for a longer exception name and 19-digit counts
        }
        finally { root.Delete(true); }
    }

    [Theory]
    [InlineData("/ok/file.jsonl", null)]
    [InlineData("/ok/file name", "may only contain")]
    [InlineData("/ok/f\u00e5.jsonl", "may only contain")]
    [InlineData("/ok/f\"x", "may only contain")]
    [InlineData("/ok//x", "may only contain")]
    [InlineData("/ok/", "may only contain")]
    [InlineData("relative", "may only contain")]
    public void The_export_path_shape_is_restricted_to_plain_characters(string path, string? why)
    {
        var result = AuditPruner.CheckExportPathShape(path);
        if (why is null) Assert.Null(result); else Assert.Contains(why, result);
    }

    [Fact]
    public void The_batch_size_must_be_at_least_one()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditPruner(null!, null!) { BatchSize = 0 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditPruner(null!, null!) { BatchSize = -5 });
    }

    [SkippableFact]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public void Syncing_a_directory_works_and_never_throws()
    {
        Skip.IfNot(OperatingSystem.IsLinux());
        var dir = Directory.CreateTempSubdirectory("gk8e");
        try
        {
            Assert.True(DirectorySync.Sync(dir.FullName));
            Assert.False(DirectorySync.Sync(Path.Combine(dir.FullName, "missing")));
            Assert.False(DirectorySync.Sync(null));
        }
        finally { dir.Delete(true); }
    }

    [SkippableFact]
    public async Task The_database_clock_behind_the_last_prune_row_refuses_the_run()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        await Seed(db.MigratorConnection, 3, 0);
        await Exec(db.MigratorConnection, "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES (gen_random_uuid(), now() + interval '1 hour', 'system:prune', 'audit.prune', 'success')");
        var (sp, pruner) = await Pruner(db.MigratorConnection);
        using var _ = sp;
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneAsync(Cut, null, false));
        Assert.Contains("earlier than the last prune", ex.Message);
        Assert.Equal(3, await Count(db.MigratorConnection, "action = 'old'"));
    }

    [SkippableFact]
    public async Task The_guard_migration_rolls_down_to_the_released_migration_and_up_again()
    {
        using var db = Db();
        const string Released = "20261027100828_AllowAuditPrune";
        await MigrateTo(db.MigratorConnection, null);
        db.GrantAppAccess();
        const string forged = "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES (gen_random_uuid(), now(), 'system:prune', 'audit.prune', 'success')";
        Assert.Equal("42501", await SqlState(db.AppConnection, forged));
        await MigrateTo(db.MigratorConnection, Released); // down: only the guard goes, the prune exception stays
        Assert.Equal(0L, await Scalar(db.MigratorConnection, "SELECT count(*) FROM pg_trigger WHERE tgname = 'audit_events_guard_prune_rows'"));
        Assert.Equal(1L, await Scalar(db.MigratorConnection, "SELECT count(*) FROM pg_proc WHERE proname = 'audit_events_immutable'"));
        await Exec(db.AppConnection, forged);
        Assert.Equal("42501", await SqlState(db.MigratorConnection, "DELETE FROM audit_events")); // still append-only without the setting
        await MigrateTo(db.MigratorConnection, null); // up again, over existing rows
        Assert.Equal("42501", await SqlState(db.AppConnection, forged));
    }

    [SkippableFact]
    public async Task Only_the_owner_can_insert_prune_rows_the_app_role_cannot_forge_them()
    {
        using var db = Db();
        await MigrateTo(db.MigratorConnection, null);
        db.GrantAppAccess();
        string Row(string actor, string action) => $"INSERT INTO audit_events (id, at, actor, action, outcome) VALUES (gen_random_uuid(), now(), '{actor}', '{action}', 'success')";
        Assert.Equal("42501", await SqlState(db.AppConnection, Row("system:prune", "audit.prune")));
        Assert.Equal("42501", await SqlState(db.AppConnection, Row("someone", "audit.prune.start")));
        Assert.Equal("42501", await SqlState(db.AppConnection, Row("system:prune", "x")));
        await Exec(db.AppConnection, Row("system", "bootstrap-admin")); // ordinary rows still insert
        await Exec(db.MigratorConnection, Row("system:prune", "audit.prune")); // the owner (the prune command) can
        Assert.Equal(2, await Count(db.MigratorConnection));
    }
}
