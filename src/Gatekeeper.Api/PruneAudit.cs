using System.Globalization;
using Gatekeeper.Infrastructure.Postgres;

namespace Gatekeeper.Api;

/// <summary>
/// `Gatekeeper.Api prune-audit --older-than &lt;days&gt; [--export &lt;file&gt; | --export-dir &lt;dir&gt;] [--dry-run] [--allow-large]` (slice 8e): deletes audit rows older than the given number of days.
/// A one-shot owner-role command like `migrate`; the serving process cannot delete audit rows.
/// </summary>
public static class PruneAudit
{
    public const int MinimumDays = 30;
    public const int MaximumDays = 36500;
    public const string Usage = "usage: prune-audit --older-than <days> [--export <file> | --export-dir <dir>] [--dry-run] [--allow-large]";
    public sealed record Options(int Days, string? Export, bool DryRun, bool AllowLarge = false, string? ExportDir = null);

    /// <summary>Parses the arguments after the command name. Returns null and a message when they are not acceptable.</summary>
    public static Options? Parse(string[] args, out string? error)
    {
        int? days = null;
        string? export = null;
        string? exportDir = null;
        var dryRun = false;
        var allowLarge = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--older-than" or "--export" or "--export-dir" when i + 1 >= args.Length:
                    return Fail($"{args[i]} needs a value. {Usage}", out error);
                case "--older-than" or "--export" or "--export-dir" when args[i + 1].StartsWith("--", StringComparison.Ordinal):
                    return Fail($"{args[i]} needs a value, not the option '{args[i + 1]}'. {Usage}", out error);
                case "--older-than" when days is null && i + 1 < args.Length:
                    if (!int.TryParse(args[++i], NumberStyles.None, CultureInfo.InvariantCulture, out var d))
                        return Fail($"--older-than must be a whole number of days. {Usage}", out error);
                    days = d;
                    break;
                case "--export" when export is null && i + 1 < args.Length:
                    export = args[++i];
                    break;
                case "--export-dir" when exportDir is null:
                    exportDir = args[++i];
                    break;
                case "--dry-run" when !dryRun:
                    dryRun = true;
                    break;
                case "--allow-large" when !allowLarge:
                    allowLarge = true;
                    break;
                default:
                    return Fail($"unexpected or repeated argument '{args[i]}'. {Usage}", out error);
            }
        }
        if (days is null) return Fail($"--older-than is required. {Usage}", out error);
        if (days < MinimumDays)
            return Fail($"--older-than must be at least {MinimumDays} days (a typo must not wipe the audit trail); got {days}.", out error);
        if (days > MaximumDays) return Fail($"--older-than must be at most {MaximumDays} days; got {days}.", out error);
        if (export is not null && exportDir is not null) return Fail("--export and --export-dir cannot be combined.", out error);
        if ((export is not null || exportDir is not null) && dryRun)
            return Fail("--export and --export-dir cannot be combined with --dry-run (a dry run deletes and writes nothing).", out error);
        if (export is not null)
        {
            export = AbsolutePath(export, "--export", 0, out error);
            if (export is null) return null;
        }
        if (exportDir is not null)
        {
            exportDir = AbsolutePath(exportDir, "--export-dir", AuditPruner.ExportFileNameLength, out error);
            if (exportDir is null) return null;
        }
        error = null;
        return new Options(days.Value, export, dryRun, allowLarge, exportDir);
    }

    /// <summary>The absolute form of an export path, or null (and the reason) when it is not acceptable. The directory form reserves room for the file name.</summary>
    private static string? AbsolutePath(string path, string option, int reserve, out string? error)
    {
        string full;
        try { full = string.IsNullOrWhiteSpace(path) || path.Contains('\0') ? "" : Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { full = ""; }
        if (reserve > 0 && full.Length > 1) full = full.TrimEnd('/'); // a directory may be given with a trailing slash
        var why = full.Length == 0 ? "a path is required" : AuditPruner.CheckExportPathShape(full, reserve);
        error = why is null ? null : $"{option}: {why}.";
        return why is null ? full : null;
    }

    private static Options? Fail(string message, out string? error)
    {
        error = message;
        return null;
    }

    public static async Task<int> RunAsync(IServiceProvider services, Options options)
    {
        // SIGTERM/SIGINT cancel the run; the pruner still writes its failure row (with a token that is not cancelled).
        using var cts = new CancellationTokenSource();
        using var term = System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGTERM, c => { c.Cancel = true; cts.Cancel(); });
        using var intr = System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGINT, c => { c.Cancel = true; cts.Cancel(); });
        try
        {
            var result = await services.GetRequiredService<AuditPruner>().PruneOlderThanAsync(options.Days, options.Export, options.DryRun, options.AllowLarge, cts.Token, options.ExportDir);
            if (options.DryRun)
            {
                Console.WriteLine($"Dry run: {result.Deleted} of {result.Total} audit rows older than {result.Before:yyyy-MM-dd HH:mm:ss}Z would be deleted.");
                if (result.Deleted > 0 && result.Deleted * 10 > result.Total * 9 && !options.AllowLarge)
                    Console.WriteLine("That is more than 90% of the table: a real run is refused unless --allow-large is given.");
            }
            else
                Console.WriteLine($"Deleted {result.Deleted} audit rows older than {result.Before:yyyy-MM-dd HH:mm:ss}Z" +
                                  (result.ExportFile is null ? "." : $"; exported to {result.ExportFile}."));
            return 0;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Npgsql messages do not include the password.
            Console.Error.WriteLine($"error: Prune failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }
}
