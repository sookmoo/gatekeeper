using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users.Sessions;

public class RevokeModel(GatekeeperApi api, WebSessions sessions, ILogger<RevokeModel> log) : PageModel
{
    public UserDto Target { get; private set; } = null!;
    public SessionDto Session { get; private set; } = null!;
    public string? AppName { get; private set; }
    public string? Error { get; private set; }
    public TimeSpan? Lifetime => HttpContext.Current().AccessLifetime;
    /// <summary>The session is the one the signed-in administrator's UI session runs on.</summary>
    public bool IsOwn => HttpContext.Current() is { } me && me.UserId == Target.Id && me.ApiSessionId == Session.Id;

    public async Task<IActionResult> OnGetAsync(Guid id, Guid sessionId, CancellationToken ct) =>
        await LoadAsync(id, sessionId, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, Guid sessionId, CancellationToken ct)
    {
        if (!await LoadAsync(id, sessionId, ct)) return NotFound();
        try
        {
            var own = IsOwn;
            await api.RevokeSessionAsync(HttpContext.Current(), sessionId, ct);
            // The UI runs on this session: end it cleanly rather than letting the next call fail.
            if (own) return Redirect(await UserAccess.EndOwnSessionAsync(api, sessions, HttpContext, ct));
            return RedirectToPage("Index", new { id, done = "revoked" });
        }
        catch (ApiException ex) when (SessionAccess.IsNotFound(ex))
        {
            return NotFound();
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Revoking a session was refused with status {Status}: {Detail}", (int)ex.Status, UserAccess.ForLog(ex.Message));
            Error = SessionAccess.RefusalText;
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    // False unless the user exists and the session is listed under them.
    private async Task<bool> LoadAsync(Guid id, Guid sessionId, CancellationToken ct)
    {
        try
        {
            var me = HttpContext.Current();
            Target = await api.GetUserAsync(me, id, ct);
            if (await SessionAccess.FindAsync(api, me, id, sessionId, ct) is not { } found) return false;
            Session = found;
            AppName = (await UserAccess.AppNamesAsync(api, me, [found.AppId], ct)).GetValueOrDefault(found.AppId);
            return true;
        }
        catch (ApiException ex) when (SessionAccess.IsNotFound(ex))
        {
            return false;
        }
    }
}
