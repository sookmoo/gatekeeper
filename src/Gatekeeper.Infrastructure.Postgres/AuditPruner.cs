using System.Text;
using System.Text.Json;
using System.Globalization;
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

    [GeneratedRegex(@"\A[0-9]+(ms|s)\z")]
    private static partial Regex LockTimeoutShape();

    /// <summary>Allowed in an export path: keeps the trace detail free of escapes, so it fits <see cref="AuditEvent.MaxField"/>.</summary>
    [GeneratedRegex(@"\A/[A-Za-z0-9._/-]*\z")]
    private static partial Regex ExportPathShape();

    /// <summary>Longest absolute export path. The longest detail is `before=.. deleted=.. exported="<path>" error=<exception name>`; this keeps it under 200.</summary>
    public const int MaxExportPath = 90;
    public const int ExportFileNameLength = 29; // audit-20261027T100000Z.jsonl

    /// <summary>Null when the absolute path is acceptable, else why not.</summary>
    public static string? CheckExportPathShape(string fullPath, int reserve = 0) =>
        fullPath.Length + reserve > MaxExportPath ? $"the absolute path must be at most {MaxExportPath - reserve} characters"
        : fullPath.EndsWith('/') || fullPath.Contains("//") || !ExportPathShape().IsMatch(fullPath) ? "the absolute path may only contain letters, digits and . _ - /"
        : null;

    private string _lockTimeout = "2s";
    private int _batchSize = DefaultBatchSize;

    /// <summary>Rows per transaction (at least 1); tests lower it.</summary>
    public int BatchSize
    {
        get => _batchSize;
        init => _batchSize = value >= 1 ? value : throw new ArgumentOutOfRangeException(nameof(value), "Batch size must be at least 1.");
    }

    /// <summary>How long a batch waits for a row lock before the prune gives up (the next run continues). Digits and ms or s only.</summary>
    public string LockTimeout
    {
        get => _lockTimeout;
        init => _lockTimeout = LockTimeoutShape().IsMatch(value) ? value : throw new ArgumentException("Lock timeout must look like 2s or 300ms.", nameof(value));
    }

    /// <summary>The application clock, compared with the database clock. Tests replace it.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>The command's entry: cut-off = database now minus <paramref name="days"/>. Export to a file, or (<paramref name="exportDir"/>) to a new file named by the run's time.</summary>
    public Task<PruneResult> PruneOlderThanAsync(int days, string? exportFile, bool dryRun, bool allowLarge, CancellationToken ct = default, string? exportDir = null) =>
        RunAsync(now => now.AddDays(-days), exportFile, exportDir, dryRun, allowLarge, ct);

    /// <summary>A run with a caller-chosen cut-off (tests, tools). Never refuses for size: that guard belongs to the command.</summary>
    public Task<PruneResult> PruneAsync(DateTimeOffset before, string? exportFile, bool dryRun, CancellationToken ct = default) =>
        RunAsync(_ => before.ToUniversalTime(), exportFile, null, dryRun, true, ct);

    private sealed class Export(FileStream stream, string path)
    {
        public FileStream Stream { get; } = stream;
        public string Path { get; } = path;
        /// <summary>File length after the last committed batch: everything beyond it belongs to a batch that did not commit.</summary>
        public long Committed { get; set; }
    }

    private async Task<PruneResult> RunAsync(Func<DateTimeOffset, DateTimeOffset> cutoffOf, string? exportFile, string? exportDir, bool dryRun, bool allowLarge, CancellationToken ct)
    {
        await using var conn = await OpenAsync(ct);
        var dbNow = await DatabaseTimeAsync(conn, ct);
        var cutoff = cutoffOf(dbNow).ToUniversalTime();
        var (planned, total, lastPrune) = await CountsAsync(conn, cutoff, ct);
        // A database clock behind the last prune row is a wrong clock (or a restore): the cut-off would be wrong too.
        if (lastPrune is { } last && dbNow < last)
            throw new InvalidOperationException($"The database clock ({dbNow:u}) is earlier than the last prune run ({last:u}); refusing to prune. Fix the clock first.");
        var large = planned > 0 && planned * 10 > total * 9; // more than 90% of the table (or all of it)
        if (dryRun) return new PruneResult(cutoff, planned, null, true, total);
        if (large && !allowLarge)
            throw new InvalidOperationException($"This would delete {planned} of {total} audit rows (more than 90%). Check --older-than and the clocks, then add --allow-large if that is intended.");

        var path = exportDir is null ? exportFile : Path.Combine(exportDir, $"audit-{dbNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture)}.jsonl");
        // Refuse an existing path (or a dangling symlink) or a missing directory before anything is recorded; the file itself is created after the start row.
        if (path is not null) CheckExportPath(path);
        var shown = path is null ? "none" : JsonSerializer.Serialize(Path.GetFullPath(path));
        var stamp = $"before={cutoff:yyyy-MM-ddTHH:mm:ssZ}";

        // The start row is written first: a start without a completion or failure row means an interrupted run.
        await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), dbNow, Actor, StartAction, null, AuditEvent.Success,
            $"{stamp} planned={planned} exported={shown}", null), ct);

        long deleted = 0;
        Export? export = null;
        try
        {
            if (path is not null) export = OpenExport(path);
            while (true)
            {
                ct.ThrowIfCancellationRequested(); // between batches only: a started batch is written and committed to the end
                var n = await DeleteBatchAsync(conn, cutoff, export, ct);
                deleted += n;
                if (n < BatchSize) break;
            }
            // Inside the handling: if this row cannot be written the failure row (with the real count) is attempted and the error surfaces.
            await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), await DatabaseTimeAsync(conn, CancellationToken.None), Actor, Action, null, AuditEvent.Success,
                $"{stamp} deleted={deleted} exported={shown}", null), CancellationToken.None);
        }
        catch (Exception ex)
        {
            // Not tied to ct: a cancelled run (SIGTERM) must still leave its trace. The file of a run that stopped before writing anything is removed.
            await TryRecordAsync(AuditEvent.Failure, $"{stamp} deleted={deleted} exported={shown} error={ex.GetType().Name}");
            await CloseExportAsync(export, removeIfEmpty: true);
            throw;
        }
        await CloseExportAsync(export, removeIfEmpty: true); // a successful run that deleted nothing leaves no empty file
        return new PruneResult(cutoff, deleted, path is null ? null : Path.GetFullPath(path), false, total);
    }

    private static async Task CloseExportAsync(Export? export, bool removeIfEmpty)
    {
        if (export is null) return;
        var empty = export.Stream.Length == 0;
        await export.Stream.DisposeAsync();
        if (removeIfEmpty && empty) TryDelete(export.Path);
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

    /// <summary>Rows to delete, rows in the table, and the time of the newest earlier prune row (if any), in one statement.</summary>
    private static async Task<(long Planned, long Total, DateTimeOffset? LastPrune)> CountsAsync(NpgsqlConnection conn, DateTimeOffset cutoff, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT count(*) FILTER (WHERE at < @c AND actor <> @a), count(*), max(at) FILTER (WHERE actor = @a) FROM audit_events", conn);
        cmd.Parameters.AddWithValue("c", cutoff.UtcDateTime);
        cmd.Parameters.AddWithValue("a", Actor);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return (r.GetInt64(0), r.GetInt64(1), r.IsDBNull(2) ? null : new DateTimeOffset(r.GetDateTime(2), TimeSpan.Zero));
    }

    private static void CheckExportPath(string path)
    {
        var info = new FileInfo(path);
        if (info.Exists || Directory.Exists(path) || info.LinkTarget is not null) throw new IOException($"The export path '{path}' already exists; it is never overwritten.");
        if (info.DirectoryName is not { } dir || !Directory.Exists(dir)) throw new DirectoryNotFoundException("The directory of the export path does not exist.");
    }

    // CreateNew = O_EXCL: no overwrite, no following a planted symlink; mode 0600 from the first byte. The directory entry is synced too.
    private static Export OpenExport(string path)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var stream = new FileStream(path, options);
        DirectorySync.Sync(Path.GetDirectoryName(Path.GetFullPath(path)));
        return new Export(stream, path);
    }

    /// <summary>
    /// One transaction: the oldest rows below the cut-off by (at, id) are deleted and returned, written to the export and flushed to disk,
    /// and only then committed. Once the delete has run, writing and committing ignore cancellation. If the write or the commit fails, the
    /// file is cut back to its length before the batch (when the rows are verifiably still in the table) so it never lists rows the table still has;
    /// if the commit did go through after all, the lines stay. Deleted rows are gone, so the next batch starts at the new oldest row.
    /// Earlier prune rows (actor system:prune) are never deleted, and the trigger refuses it as well.
    /// </summary>
    private async Task<int> DeleteBatchAsync(NpgsqlConnection conn, DateTimeOffset cutoff, Export? export, CancellationToken ct)
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

        try
        {
            if (export is not null && rows.Count > 0)
            {
                foreach (var e in rows.OrderBy(e => e.At).ThenBy(e => e.Id, Comparer<Guid>.Create(AuditKey.CompareIds)))
                    await export.Stream.WriteAsync(Encoding.UTF8.GetBytes(Line(e) + "\n"), CancellationToken.None);
                await export.Stream.FlushAsync(CancellationToken.None);
                export.Stream.Flush(flushToDisk: true);
            }
            await tx.CommitAsync(CancellationToken.None);
        }
        catch when (export is not null)
        {
            // Did the commit happen? Look from outside: all rows still there means no (cut the file back); none there means yes (keep the lines).
            var present = await StillPresentAsync(rows.Select(r => r.Id).ToArray());
            if (present == rows.Count)
            {
                try { export.Stream.SetLength(export.Committed); export.Stream.Flush(flushToDisk: true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* the original error is the one to report */ }
                throw;
            }
            if (present != 0) throw;
        }
        if (export is not null) export.Committed = export.Stream.Length;
        return rows.Count;
    }

    /// <summary>How many of these rows exist; -1 when that cannot be found out.</summary>
    private async Task<int> StillPresentAsync(Guid[] ids)
    {
        try
        {
            await using var conn = await OpenAsync(CancellationToken.None);
            await using var cmd = new NpgsqlCommand("SELECT count(*) FROM audit_events WHERE id = ANY(@ids)", conn);
            cmd.Parameters.AddWithValue("ids", ids);
            return (int)(long)(await cmd.ExecuteScalarAsync())!;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return -1; }
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
