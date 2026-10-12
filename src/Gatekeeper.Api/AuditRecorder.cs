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

    /// <summary>The acting identity of an authenticated request: the token's subject.</summary>
    public static string ActorOf(HttpContext http) => http.User.FindFirst("sub")?.Value ?? "anonymous";
}

/// <summary>Records every state-changing management call after it ran: who, what, on which ids, and whether it worked.</summary>
public sealed class AuditFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var http = ctx.HttpContext;
        if (HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method)) return await next(ctx);

        var recorder = http.RequestServices.GetRequiredService<AuditRecorder>();
        var pattern = (http.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? http.Request.Path.Value ?? "";
        var action = $"{http.Request.Method} {pattern.TrimEnd('/')}";
        var target = string.Join(" ", http.Request.RouteValues.Select(kv => $"{kv.Key}={kv.Value}"));
        var actor = AuditRecorder.ActorOf(http);
        try
        {
            var result = await next(ctx);
            var status = (result as IStatusCodeHttpResult)?.StatusCode ?? StatusCodes.Status200OK;
            await recorder.RecordAsync(http, actor, action, target, status is >= 200 and < 300, $"status {status}");
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            await recorder.RecordAsync(http, actor, action, target, false, ex.GetType().Name);
            throw;
        }
    }
}
