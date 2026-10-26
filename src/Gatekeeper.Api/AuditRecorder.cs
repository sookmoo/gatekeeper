using Gatekeeper.Application;

namespace Gatekeeper.Api;

/// <summary>
/// Best-effort audit writes for the API: a failing audit store is logged but never turns a completed change or a
/// login into an error (availability over completeness; the failure is visible in the log).
/// </summary>
public sealed class AuditRecorder(AuditService audit, AuditCoalescer coalescer, ILogger<AuditRecorder> logger)
{
    public async Task RecordAsync(HttpContext http, string actor, string action, string? target, bool success, string? detail = null, bool refusal = false)
    {
        try
        {
            // Only a refusal that changed nothing (the caller says so) from a non-administrator may be coalesced; see AuditCoalescer.
            if (refusal && !success && !IsAdmin(http) && !await AdmitAsync(actor, action, Gatekeeper.Domain.AuditEvent.Failure)) return;
            // Not tied to the request token: a client that disconnects must not lose the record of what it did.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await audit.RecordAsync(actor, action, target, success, detail, http.Connection.RemoteIpAddress?.ToString(), cts.Token);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError("Could not write audit event {Action}: {Type}", action, ex.GetType().Name);
        }
    }

    /// <summary>A valid token that an authorization policy refused (403) on a /v1 route: actor = sub, action = the route, outcome forbidden.</summary>
    public async Task RecordForbiddenAsync(HttpContext http)
    {
        try
        {
            var actor = ActorOf(http);
            var forbiddenAction = AuditMiddleware.Describe(http, out _);
            if (!IsAdmin(http) && !await AdmitAsync(actor, forbiddenAction, Gatekeeper.Domain.AuditEvent.Forbidden)) return;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await audit.RecordOutcomeAsync(ActorOf(http), AuditMiddleware.Describe(http, out var target), target, Gatekeeper.Domain.AuditEvent.Forbidden,
                "status 403", http.Connection.RemoteIpAddress?.ToString(), cts.Token);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError("Could not write audit event for a forbidden request: {Type}", ex.GetType().Name);
        }
    }

    private static bool IsAdmin(HttpContext http) => http.User.IsInRole(Gatekeeper.Domain.Reserved.AdminRole);

    /// <summary>Asks the coalescer; writes the summaries of ended windows it hands back. False: count the row only.</summary>
    private async Task<bool> AdmitAsync(string actor, string action, string outcome)
    {
        var write = coalescer.Admit(actor, action, outcome, out var due);
        await WriteSummariesAsync(due);
        return write;
    }

    /// <summary>
    /// One row per summary, written directly (never coalesced itself), in parallel under one overall budget (the 5 s of a single write when no token is given).
    /// A failing store is logged with what was lost; the summary is put back once for the next sweep.
    /// </summary>
    public async Task WriteSummariesAsync(IEnumerable<AuditSummary> summaries, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(5));
        await Task.WhenAll(summaries.Select(async s =>
        {
            try
            {
                await audit.RecordOutcomeAsync(s.Actor, s.Action, null, s.Outcome, s.Detail, null, cts.Token);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                logger.LogError("Could not write an audit summary ({Type}); actor {Actor}, action {Action}, outcome {Outcome}, suppressed {Count}, since {Since:O}{Retry}",
                    ex.GetType().Name, s.Actor, s.Action, s.Outcome, s.Count, s.Since, s.Attempts < 1 ? "; will retry once" : "; given up");
                coalescer.Requeue(s);
            }
        }));
    }

    public Task RecordAsync(string actor, string action, string? target, bool success, string? detail = null) =>
        audit.RecordAsync(actor, action, target, success, detail);

    /// <summary>
    /// How a failed attempt names who it tried to be. Only names that exist are recorded; anything else (a typo, a probe, or a
    /// password or secret typed into the wrong field) is recorded as its length only, because the trail cannot be redacted.
    /// </summary>
    public static string Attempted(string kind, string? name, bool known) =>
        known && name is not null ? $"{kind}={name}" : $"{kind}=<unknown, {name?.Length ?? 0} chars>";

    /// <summary>The acting identity of an authenticated request: the token's subject.</summary>
    public static string ActorOf(HttpContext http) => http.User.FindFirst("sub")?.Value ?? "anonymous";
}

/// <summary>
/// Records every state-changing management call after it ran: who, what, on which ids, and whether it worked. It is
/// middleware (not an endpoint filter) so requests that fail binding (malformed JSON, wrong content type, oversized body)
/// are recorded too. It sits after authorization, so requests rejected with 401/403 are not recorded.
/// </summary>
public sealed partial class AuditMiddleware(RequestDelegate next)
{
    /// <summary>
    /// A row that carries a <c>reason=</c> note (wrong current password, busy after a verified guess, same password) is never coalesced: those mark a spent
    /// guess or a decision and are bounded by their own throttles, so a flood of malformed requests must not hide them.
    /// </summary>
    private static bool Coalescible(HttpContext http) => http.Items[NoteKey] is not string n || !n.Contains("reason=", StringComparison.Ordinal);

    /// <summary>An endpoint can leave a short note here (HttpContext.Items) that is appended to the audit detail.</summary>
    public const string NoteKey = "audit.note";

    /// <summary>An endpoint sets this (HttpContext.Items) to have no audit row written for this request (a throttled attempt: the failures before it were recorded).</summary>
    public const string SkipKey = "audit.skip";

    /// <summary>An endpoint sets this when its own 403 is already recorded by this middleware, so <see cref="ForbiddenAuditMiddleware"/> adds no second row.</summary>
    public const string SelfAuditedKey = "audit.self";

    [System.Text.RegularExpressions.GeneratedRegex(@"\{([^{}:]+):[^{}]*\}")]
    private static partial System.Text.RegularExpressions.Regex RouteConstraint();

    /// <summary>The audit action of a request ("PUT /v1/users/{id}/password") and its target (the route values).</summary>
    public static string Describe(HttpContext http, out string target)
    {
        var pattern = (http.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? http.Request.Path.Value ?? "";
        target = string.Join(" ", http.Request.RouteValues.Select(kv => $"{kv.Key}={kv.Value}"));
        // Readable and stable: drop route constraints ({id:guid} -> {id}) so filters can be typed by hand.
        return $"{http.Request.Method} {RouteConstraint().Replace(pattern.TrimEnd('/'), "{$1}")}";
    }

    public async Task InvokeAsync(HttpContext http)
    {
        var path = http.Request.Path;
        if (!path.StartsWithSegments("/v1") || path.StartsWithSegments("/v1/auth") // logins audit themselves
            || HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method) || HttpMethods.IsOptions(http.Request.Method)
            || http.User.Identity?.IsAuthenticated != true)
        {
            await next(http);
            return;
        }

        var recorder = http.RequestServices.GetRequiredService<AuditRecorder>();
        var action = Describe(http, out var target);
        var actor = AuditRecorder.ActorOf(http);
        try
        {
            await next(http);
        }
        catch (Exception) when (http.Items.ContainsKey(SkipKey))
        {
            throw; // the endpoint asked for no row (a throttled or busy attempt)
        }
        catch (OperationCanceledException)
        {
            // The client went away or timed out; the change may already be committed, so the trail must still show the attempt.
            // "cancelled" means the outcome is unknown: the change may or may not have been committed.
            await recorder.RecordAsync(http, actor, action, target, false, http.Items[NoteKey] is string cancelNote ? $"cancelled; {cancelNote}" : "cancelled");
            throw;
        }
        catch (Exception ex)
        {
            // Domain exceptions are turned into responses by the outer error middleware; record what went wrong. A domain refusal (not an
            // unavailable store: that outcome is unknown) changed nothing and may be coalesced for a non-administrator.
            await recorder.RecordAsync(http, actor, action, target, false, http.Items[NoteKey] is string failNote ? $"{ex.GetType().Name}; {failNote}" : ex.GetType().Name,
                refusal: (ex is Gatekeeper.Domain.GatekeeperException and not Gatekeeper.Domain.StoreUnavailableException
                    || ex is BadHttpRequestException { StatusCode: >= 400 and < 500 }) && Coalescible(http));
            throw;
        }
        if (http.Items.ContainsKey(SkipKey)) return;
        var status = http.Response.StatusCode;
        await recorder.RecordAsync(http, actor, action, target, status is >= 200 and < 300,
            http.Items[NoteKey] is string note ? $"status {status}; {note}" : $"status {status}", refusal: status is >= 400 and < 500 && Coalescible(http));
    }
}

/// <summary>
/// Records a 403 on a /v1 route for an authenticated caller (a valid token the policy refused, for example a self-service token on a
/// management route). Sits before authorization, so it sees the refusal; 401s are still not recorded.
/// </summary>
public sealed class ForbiddenAuditMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext http)
    {
        await next(http);
        var path = http.Request.Path;
        if (http.Response.StatusCode == StatusCodes.Status403Forbidden && path.StartsWithSegments("/v1") && !path.StartsWithSegments("/v1/auth")
            && http.User.Identity?.IsAuthenticated == true && !http.Items.ContainsKey(AuditMiddleware.SelfAuditedKey))
            await http.RequestServices.GetRequiredService<AuditRecorder>().RecordForbiddenAsync(http);
    }
}
