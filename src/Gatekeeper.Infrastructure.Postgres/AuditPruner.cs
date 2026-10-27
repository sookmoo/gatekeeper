using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Gatekeeper.Infrastructure.Postgres;

/// <summary>What a prune did (or, for a dry run, would do). <paramref name="Total"/> is the number of rows in the table when it started.</summary>
public sealed record PruneResult(DateTimeOffset Before, long Deleted, string? ExportFile, bool DryRun, long Total = 0);

/// <summary>
/// Slice 8e: deletes audit rows older than a cut-off. Only for the owner role (the connection of `migrate`): the audit trigger lets a DELETE
/// pass only for the table owner inside a transaction that set gatekeeper.audit_prune = 'on'. The serving process never calls this.
/// Time comes from the database clock (cut-off and trace rows); the run is refused when the application clock differs by more than 5 minutes.
/// </summary>
public sealed partial class AuditPruner(IDbContextFactory<GatekeeperDbContext> factory, IAuditRepository audit)
{
    public const string Action = "audit.prune";
    public const string StartAction = "audit.prune.start";
    public const string Actor = "system:prune";
    public const int DefaultBatchSize = 5000;
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

    [GeneratedRegex(@"^\d+(ms|s)$")]
    private static partial Regex LockTimeoutShape();

    private string _lockTimeout = "2s";

    /// <summary>Rows per transaction; tests lower it.</summary>
    public int BatchSize { get; init; } = DefaultBatchSize;

    /// <summary>How long a batch waits for a row lock before the prune gives up (the next run continues). Digits and ms or s only.</summary>
    public string LockTimeout
    {
        get => _lockTimeout;
        init => _lockTimeout = LockTimeoutShape().IsMatch(value) ? value : throw new ArgumentException("Lock timeout must look like 2s or 300ms.", nameof(value));
    }

    /// <summary>The application clock, compared with the database clock. Tests replace it.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>The command's entry: cut-off = database now minus <paramref name="days"/>, and the guard against wiping (nearly) the whole table.</summary>
    public async Task<PruneResult> PruneOlderThanAsync(int days, string? exportFile, bool dryRun, bool allowLarge, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        var now = await DatabaseTimeAsync(conn, ct);
        var cutoff = now.AddDays(-days);
        var planned = await CountAsync(conn, cutoff, ct);
        var total = await CountAsync(conn, null, ct);
        // More than 90% of the table (or all of it): a wrong retention or a wrong clock looks exactly like this.
        var large = planned > 0 && planned * 10 > total * 9;
        if (large && !allowLarge && !dryRun)
            throw new InvalidOperationException($"This would delete {planned} of {total} audit rows (more than 90%). Check --older-than and the clocks, then add --allow-large if that is intended.");
        if (dryRun) return new PruneResult(cutoff, planned, null, true, total);
        return await PruneAsync(cutoff, exportFile, false, ct);
    }

    public async Task<PruneResult> PruneAsync(DateTimeOffset before, string? exportFile, bool dryRun, CancellationToken ct = default)
    {
        var cutoff = before.ToUniversalTime();
        await using var conn = await OpenAsync(ct);
        var dbNow = await DatabaseTimeAsync(conn, ct);
        var planned = await CountAsync(conn, cutoff, ct);
        var total = dryRun ? await CountAsync(conn, null, ct) : 0;
        if (dryRun) return new PruneResult(cutoff, planned, null, true, total);

        // Refuse an existing path (or a dangling symlink) or a missing directory before anything is recorded; the file itself is created after the start row.
        if (exportFile is not null) CheckExportPath(exportFile);
        var shown = exportFile is null ? "none" : JsonSerializer.Serialize(Path.GetFullPath(exportFile));
        var stamp = $"before={cutoff:yyyy-MM-ddTHH:mm:ssZ}";

        // The start row is written first: a start without a completion row means an interrupted run.
        await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), dbNow, Actor, StartAction, null, AuditEvent.Success,
            $"{stamp} planned={planned} exported={shown}", null), ct);

        long deleted = 0;
        FileStream? export = null;
        try
        {
            export = exportFile is null ? null : OpenExport(exportFile);
            while (true)
            {
                var n = await DeleteBatchAsync(conn, cutoff, export, ct);
                deleted += n;
                if (n < BatchSize) break;
            }
        }
        catch (Exception ex)
        {
            // Not tied to ct: a cancelled run (SIGTERM) must still leave its trace. The file of a run that stopped before writing anything is removed.
            await TryRecordAsync(AuditEvent.Failure, $"{stamp} deleted={deleted} exported={shown} error={ex.GetType().Name}");
            if (export is not null && exportFile is not null)
            {
                var empty = export.Length == 0;
                await export.DisposeAsync();
                export = null;
                if (empty) TryDelete(exportFile);
            }
            throw;
        }
        finally
        {
            if (export is not null) await export.DisposeAsync();
        }
        await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), await DatabaseTimeAsync(conn, CancellationToken.None), Actor, Action, null, AuditEvent.Success,
            $"{stamp} deleted={deleted} exported={shown}", null), CancellationToken.None);
        return new PruneResult(cutoff, deleted, exportFile is null ? null : Path.GetFullPath(exportFile), false);
    }

    private async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        string connectionString;
        await using (var db = await factory.CreateDbContextAsync(ct))
            connectionString = db.Database.GetConnectionString() ?? throw new InvalidOperationException("No connection string.");
        var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }

    /// <summary>The database clock; throws when the application clock is more than <see cref="MaxClockSkew"/> away from it.</summary>
    private async Task<DateTimeOffset> DatabaseTimeAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("SELECT clock_timestamp()", conn);
        var db = new DateTimeOffset((DateTime)(await cmd.ExecuteScalarAsync(ct))!, TimeSpan.Zero);
        var skew = (db - Clock.GetUtcNow()).Duration();
        if (skew > MaxClockSkew)
            throw new InvalidOperationException($"The application clock and the database clock differ by {skew.TotalMinutes:F0} minutes (limit {MaxClockSkew.TotalMinutes:F0}); refusing to prune. Fix the clocks first.");
        return db;
    }

    private async Task TryRecordAsync(string outcome, string detail)
    {
        try
        {
            await using var conn = await OpenAsync(CancellationToken.None);
            var at = await DatabaseTimeAsync(conn, CancellationToken.None);
            await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), at, Actor, Action, null, outcome, detail, null), CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The original failure is the one that surfaces; say that its trace row is missing.
            Console.Error.WriteLine($"warning: could not write the audit.prune {outcome} row: {ex.GetType().Name}");
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* leave it */ }
    }

    private static async Task<long> CountAsync(NpgsqlConnection conn, DateTimeOffset? cutoff, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(cutoff is null ? "SELECT count(*) FROM audit_events" : "SELECT count(*) FROM audit_events WHERE at < @c AND actor <> @a", conn);
        if (cutoff is { } c)
        {
            cmd.Parameters.AddWithValue("c", c.UtcDateTime);
            cmd.Parameters.AddWithValue("a", Actor);
        }
        return (long)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static void CheckExportPath(string path)
    {
        var info = new FileInfo(path);
        if (info.Exists || Directory.Exists(path) || info.LinkTarget is not null) throw new IOException($"The export path '{path}' already exists; it is never overwritten.");
        if (info.DirectoryName is not { } dir || !Directory.Exists(dir)) throw new DirectoryNotFoundException("The directory of the export path does not exist.");
    }

    // CreateNew = O_EXCL: no overwrite, no following a planted symlink; mode 0600 from the first byte. The directory entry is synced too.
    private static FileStream OpenExport(string path)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var stream = new FileStream(path, options);
        SyncDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
        return stream;
    }

    private static void SyncDirectory(string? dir)
    {
        if (dir is null || OperatingSystem.IsWindows()) return;
        try
        {
            using var handle = File.OpenHandle(dir, FileMode.Open, FileAccess.Read);
            RandomAccess.FlushToDisk(handle);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException) { /* best effort */ }
    }

    /// <summary>
    /// One transaction: the oldest rows below the cut-off by (at, id) are deleted and returned, written to the export and flushed to disk,
    /// and only then committed. A failing export rolls the batch back. Deleted rows are gone, so the next batch starts at the new oldest row.
    /// Earlier prune rows (actor system:prune) are never deleted, and the trigger refuses it as well.
    /// </summary>
    private async Task<int> DeleteBatchAsync(NpgsqlConnection conn, DateTimeOffset cutoff, FileStream? export, CancellationToken ct)
    {
        await using var tx = await conn.BeginTransactionAsync(ct);
        await using (var set = new NpgsqlCommand("SELECT set_config('lock_timeout', @t, true), set_config('gatekeeper.audit_prune', 'on', true)", conn, tx))
        {
            set.Parameters.AddWithValue("t", LockTimeout);
            await set.ExecuteNonQueryAsync(ct);
        }

        var rows = new List<AuditEvent>();
        await using (var cmd = new NpgsqlCommand(
            "DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE at < @c AND actor <> @a ORDER BY at, id LIMIT @n) " +
            "RETURNING id, at, actor, action, target, outcome, detail, address", conn, tx))
        {
            cmd.Parameters.AddWithValue("c", cutoff.UtcDateTime);
            cmd.Parameters.AddWithValue("a", Actor);
            cmd.Parameters.AddWithValue("n", BatchSize);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                rows.Add(new AuditEvent(r.GetGuid(0), new DateTimeOffset(r.GetDateTime(1), TimeSpan.Zero), r.GetString(2), r.GetString(3),
                    r.IsDBNull(4) ? null : r.GetString(4), r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6), r.IsDBNull(7) ? null : r.GetString(7)));
        }

        if (export is not null && rows.Count > 0)
        {
            foreach (var e in rows.OrderBy(e => e.At).ThenBy(e => e.Id, Comparer<Guid>.Create(AuditKey.CompareIds)))
                await export.WriteAsync(Encoding.UTF8.GetBytes(Line(e) + "\n"), ct);
            await export.FlushAsync(ct);
            export.Flush(flushToDisk: true);
        }
        await tx.CommitAsync(ct);
        return rows.Count;
    }

    private static string Line(AuditEvent e) => JsonSerializer.Serialize(new
    {
        id = e.Id,
        at = e.At.UtcDateTime.ToString("O"),
        actor = e.Actor,
        action = e.Action,
        target = e.Target,
        outcome = e.Outcome,
        detail = e.Detail,
        address = e.Address,
    });
}
