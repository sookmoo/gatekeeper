using Gatekeeper.Application;

namespace Gatekeeper.Api;

/// <summary>
/// Best-effort audit writes for the API: a failing audit store is logged but never turns a completed change or a
/// login into an error (availability over completeness; the failure is visible in the log).
/// </summary>
public sealed class AuditRecorder(AuditService audit, ILogger<AuditRecorder> logger)
{
    public async Task RecordAsync(HttpContext http, string actor, string action, string? target, bool success, string? detail = null)
    {
        try
        {
            // Not tied to the request token: a client that disconnects must not lose the record of what it did.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await audit.RecordAsync(actor, action, target, success, detail, http.Connection.RemoteIpAddress?.ToString(), cts.Token);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError("Could not write audit event {Action}: {Type}", action, ex.GetType().Name);
        }
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
    [System.Text.RegularExpressions.GeneratedRegex(@"\{([^{}:]+):[^{}]*\}")]
    private static partial System.Text.RegularExpressions.Regex RouteConstraint();

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
        var pattern = (http.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? path.Value ?? "";
        // Readable and stable: drop route constraints ({id:guid} -> {id}) so filters can be typed by hand.
        var action = $"{http.Request.Method} {RouteConstraint().Replace(pattern.TrimEnd('/'), "{$1}")}";
        var target = string.Join(" ", http.Request.RouteValues.Select(kv => $"{kv.Key}={kv.Value}"));
        var actor = AuditRecorder.ActorOf(http);
        try
        {
            await next(http);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Domain exceptions are turned into responses by the outer error middleware; record what went wrong.
            await recorder.RecordAsync(http, actor, action, target, false, ex.GetType().Name);
            throw;
        }
        var status = http.Response.StatusCode;
        await recorder.RecordAsync(http, actor, action, target, status is >= 200 and < 300, $"status {status}");
    }
}
