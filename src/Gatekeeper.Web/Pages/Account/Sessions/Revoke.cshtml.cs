using Gatekeeper.Web.Pages.Users;
using Gatekeeper.Web.Pages.Users.Sessions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Account.Sessions;

/// <summary>Confirmation for ending one of the signed-in user's own sessions. Ending the current one ends this web session too (as in 5f).</summary>
public class RevokeModel(GatekeeperApi api, WebSessions sessions, TimeProvider time, ILogger<RevokeModel> log) : PageModel
{
    public OwnSessionDto Session { get; private set; } = null!;
    public string? Error { get; private set; }
    public TimeSpan? Lifetime => HttpContext.Current().AccessLifetime;

    public async Task<IActionResult> OnGetAsync(Guid sessionId, CancellationToken ct) =>
        await LoadAsync(sessionId, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid sessionId, CancellationToken ct)
    {
        if (!await LoadAsync(sessionId, ct)) return NotFound();
        try
        {
            var current = Session.Current;
            await api.RevokeOwnSessionAsync(HttpContext.Current(), sessionId, ct);
            // The UI runs on this session: end it cleanly rather than letting the next call fail.
            if (current) return Redirect(await UserAccess.EndOwnSessionAsync(api, sessions, HttpContext, ct));
            return RedirectToPage("/Account/Index", new { done = "revoked" });
        }
        catch (ApiException ex) when (SessionAccess.IsNotFound(ex))
        {
            return NotFound();
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Revoking an own session was refused with status {Status}: {Detail}", (int)ex.Status, UserAccess.ForLog(ex.Message));
            Error = SessionAccess.RefusalText;
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    // False unless the session is one of the signed-in user's own active ones (another user's and an unknown id look the same).
    private async Task<bool> LoadAsync(Guid sessionId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var found = (await api.ListOwnSessionsAsync(HttpContext.Current(), ct)).FirstOrDefault(s => s.Id == sessionId);
        if (found is null || IndexModel.SessionState(found, now) != "active") return false;
        Session = found;
        return true;
    }
}
