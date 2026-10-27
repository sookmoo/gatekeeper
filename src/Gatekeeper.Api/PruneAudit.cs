using System.Globalization;
using Gatekeeper.Infrastructure.Postgres;

namespace Gatekeeper.Api;

/// <summary>
/// `Gatekeeper.Api prune-audit --older-than &lt;days&gt; [--export &lt;file&gt;] [--dry-run]` (slice 8e): deletes audit rows older than the given number of days.
/// A one-shot owner-role command like `migrate`; the serving process cannot delete audit rows.
/// </summary>
public static class PruneAudit
{
    public const int MinimumDays = 30;
    public const int MaximumDays = 36500;
    public const string Usage = "usage: prune-audit --older-than <days> [--export <file>] [--dry-run] [--allow-large]";
    // The trace rows' detail is kept short; the whole (absolute) export path must fit in it.
    private const int MaxExportPath = 100;

    public sealed record Options(int Days, string? Export, bool DryRun, bool AllowLarge = false);

    /// <summary>Parses the arguments after the command name. Returns null and a message when they are not acceptable.</summary>
    public static Options? Parse(string[] args, out string? error)
    {
        int? days = null;
        string? export = null;
        var dryRun = false;
        var allowLarge = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--older-than" or "--export" when i + 1 < args.Length && args[i + 1].StartsWith("--", StringComparison.Ordinal):
                    return Fail($"{args[i]} needs a value, not the option '{args[i + 1]}'. {Usage}", out error);
                case "--older-than" when days is null && i + 1 < args.Length:
                    if (!int.TryParse(args[++i], NumberStyles.None, CultureInfo.InvariantCulture, out var d))
                        return Fail($"--older-than must be a whole number of days. {Usage}", out error);
                    days = d;
                    break;
                case "--export" when export is null && i + 1 < args.Length:
                    export = args[++i];
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
        if (export is not null)
        {
            if (dryRun) return Fail("--export cannot be combined with --dry-run (a dry run deletes and writes nothing).", out error);
            // Judge the absolute path: that is what is created and what the trace rows name.
            string full;
            try { full = string.IsNullOrWhiteSpace(export) || export.Contains('\0') ? "" : Path.GetFullPath(export); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { full = ""; }
            if (full.Length == 0 || full.Length > MaxExportPath || full.EndsWith('/') || full.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '"' or '\\'))
                return Fail($"--export needs a file path whose absolute form is at most {MaxExportPath} characters, without spaces, control characters, quotes or backslashes.", out error);
            export = full;
        }
        error = null;
        return new Options(days.Value, export, dryRun, allowLarge);
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
            var result = await services.GetRequiredService<AuditPruner>().PruneOlderThanAsync(options.Days, options.Export, options.DryRun, options.AllowLarge, cts.Token);
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
