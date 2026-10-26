using Gatekeeper.Application;

namespace Gatekeeper.Api;

/// <summary>What was suppressed for one (actor, action, outcome) key: written as one row so the trail shows that, and how much, was left out.</summary>
public sealed record AuditSummary(string Actor, string Action, string Outcome, int Count, DateTimeOffset Since, int Attempts = 0)
{
    public string Detail => $"suppressed={Count} since={Since.UtcDateTime:O}";
}

/// <summary>
/// Bounds the audit rows a non-administrator can cause with refused requests (403s, 400s, 404s ...): per (actor, action, outcome) the first
/// <c>freePerWindow</c> rows in a window are written as always, further ones are only counted, and the count is written as one summary row
/// (same actor, action and outcome; detail <c>suppressed=n since=t</c>) once the window is over. Only callers that decide a row is a
/// refusal that changed nothing may ask; success rows, unknown outcomes and administrators' rows never come here.
/// <para>
/// Per process and in memory: a summary that has not been written when the process dies is lost (the first rows of every window were
/// written). Memory is bounded by <c>maxKeys</c> live keys; when the table is full of live windows a new key is not coalesced (its row is written),
/// so a full table can never hide anything. Summaries are never passed through the coalescer again.
/// </para>
/// </summary>
public sealed class AuditCoalescer(TimeProvider? time = null, int freePerWindow = 5, TimeSpan? window = null, int maxKeys = 10_000)
{
    private sealed class Slot(DateTimeOffset start)
    {
        public DateTimeOffset Start = start;
        public int Written;
        public int Suppressed;
    }

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(1);
    private readonly Dictionary<(string, string, string), Slot> _slots = new();
    private readonly List<AuditSummary> _retry = [];
    private DateTimeOffset _lastFullSweep = DateTimeOffset.MinValue;
    private readonly object _gate = new();

    private const int MaxRetry = 1000;

    public int TrackedKeys { get { lock (_gate) return _slots.Count; } }

    /// <summary>True when the row is to be written. <paramref name="due"/> lists summaries of windows that ended (to be written by the caller).</summary>
    public bool Admit(string actor, string action, string outcome, out IReadOnlyList<AuditSummary> due)
    {
        var now = _time.GetUtcNow();
        var key = (actor, action, outcome);
        lock (_gate)
        {
            var list = new List<AuditSummary>();
            due = list;
            if (_slots.TryGetValue(key, out var slot))
            {
                if (now - slot.Start >= _window)
                {
                    if (slot.Suppressed > 0) list.Add(new AuditSummary(actor, action, outcome, slot.Suppressed, slot.Start));
                    slot.Start = now;
                    slot.Written = 1;
                    slot.Suppressed = 0;
                    return true;
                }
                if (slot.Written < freePerWindow)
                {
                    slot.Written++;
                    return true;
                }
                slot.Suppressed++;
                return false;
            }
            // A full table must not turn every refusal into an O(n) scan: sweep at most once a second, otherwise fail open below.
            if (_slots.Count >= maxKeys && now - _lastFullSweep >= TimeSpan.FromSeconds(1))
            {
                _lastFullSweep = now;
                SweepLocked(now, all: false, list);
            }
            if (_slots.Count >= maxKeys) return true; // full of live windows: fail open (write the row)
            _slots[key] = new Slot(now) { Written = 1 };
            return true;
        }
    }

    /// <summary>Summaries of windows that have ended (and forgets those keys); with <paramref name="all"/> also the running ones (shutdown).</summary>
    public IReadOnlyList<AuditSummary> TakeDue(bool all = false)
    {
        var list = new List<AuditSummary>();
        lock (_gate)
        {
            SweepLocked(_time.GetUtcNow(), all, list);
            list.AddRange(_retry);
            _retry.Clear();
        }
        return list;
    }

    /// <summary>A summary that could not be written is put back once (capped), to be returned by the next <see cref="TakeDue"/>.</summary>
    public void Requeue(AuditSummary failed)
    {
        if (failed.Attempts >= 1) return;
        lock (_gate)
            if (_retry.Count < MaxRetry) _retry.Add(failed with { Attempts = failed.Attempts + 1 });
    }

    private void SweepLocked(DateTimeOffset now, bool all, List<AuditSummary> into)
    {
        foreach (var (key, slot) in _slots.ToArray())
        {
            if (!all && now - slot.Start < _window) continue;
            if (slot.Suppressed > 0) into.Add(new AuditSummary(key.Item1, key.Item2, key.Item3, slot.Suppressed, slot.Start));
            _slots.Remove(key);
        }
    }
}

/// <summary>
/// Writes the summaries of ended windows once a minute, and everything still pending when the host stops: in <c>StopAsync</c>, and once more after
/// the server has stopped (<c>ApplicationStopped</c>), which catches refusals that were still being served while it drained. Each flush is bounded
/// to 5 s in total. What is still pending when the process dies (crash, kill, store down) is lost; see Q7d-2.
/// </summary>
public sealed class AuditSummaryFlusher(AuditCoalescer coalescer, AuditRecorder recorder, IHostApplicationLifetime lifetime) : BackgroundService
{
    private static readonly TimeSpan FlushBudget = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        lifetime.ApplicationStopped.Register(() => FlushAllAsync(CancellationToken.None).GetAwaiter().GetResult());
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken)) await recorder.WriteSummariesAsync(coalescer.TakeDue(), stoppingToken);
        }
        catch (OperationCanceledException)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        await FlushAllAsync(cancellationToken);
    }

    private async Task FlushAllAsync(CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(FlushBudget);
        await recorder.WriteSummariesAsync(coalescer.TakeDue(all: true), budget.Token);
    }
}

/// <summary>
/// Per-user limit on the state-changing calls of /v1/me (a sliding window, per process): over the limit the call is 429 with Retry-After
/// and no audit row, so a self-service token cannot turn writes into unbounded audit rows. GETs are not counted.
/// </summary>
public sealed class MeWriteLimitMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext http)
    {
        var method = http.Request.Method;
        if (!http.Request.Path.StartsWithSegments("/v1/me") || HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method)
            || http.User.Identity?.IsAuthenticated != true || AdminAccessCheck.Subject(http.User) is not var (userId, _))
        {
            await next(http);
            return;
        }
        // The bucket is per session, so a stolen session cannot use up the owner's other sessions' share and the owner can end it from another
        // session. The password change is not counted (it has its own throttles).
        var path = http.Request.Path;
        var exempt = HttpMethods.IsPut(method) && path.Equals("/v1/me/password", StringComparison.OrdinalIgnoreCase);
        var throttle = http.RequestServices.GetRequiredKeyedService<LoginThrottle>(KeyName);
        var key = AdminAccessCheck.Subject(http.User)!.Value.SessionId is { } sid ? $"me:{userId}:{sid}" : $"me:{userId}";
        if (exempt || throttle.TryReserve(key, out var wait))
        {
            await next(http);
            return;
        }
        http.Items[AuditMiddleware.SkipKey] = true;
        http.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
        await Results.Problem("Too many requests. Try again later.", statusCode: StatusCodes.Status429TooManyRequests).ExecuteAsync(http);
    }

    public const string KeyName = "meWrites";
}
