using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users.Sessions;

public class RevokeAllModel(GatekeeperApi api, WebSessions sessions, TimeProvider time, ILogger<RevokeAllModel> log) : PageModel
{
    public UserDto Target { get; private set; } = null!;
    public int Count { get; private set; }
    public bool CountIsLowerBound { get; private set; }
    public string? Error { get; private set; }
    public TimeSpan? Lifetime => HttpContext.Current().AccessLifetime;
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Target.Id;

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, true, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, false, ct)) return NotFound(); // only the user: the API's own answer says how many it ended
        try
        {
            var self = IsSelf;
            var revoked = await api.RevokeUserSessionsAsync(HttpContext.Current(), id, ct);
            if (self) return Redirect(await UserAccess.EndOwnSessionAsync(api, sessions, HttpContext, ct));
            return RedirectToPage("Index", new { id, done = "revokedall", n = revoked });
        }
        catch (ApiException ex) when (SessionAccess.IsNotFound(ex))
        {
            return NotFound();
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Revoking all sessions was refused with status {Status}: {Detail}", (int)ex.Status, UserAccess.ForLog(ex.Message));
            Error = SessionAccess.RefusalText;
            try { await CountAsync(id, ct); } // the page is shown again with its form
            catch (ApiException e) when (SessionAccess.IsNotFound(e)) { return NotFound(); }
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    private async Task<bool> LoadAsync(Guid id, bool count, CancellationToken ct)
    {
        try
        {
            Target = await api.GetUserAsync(HttpContext.Current(), id, ct);
            if (count) await CountAsync(id, ct);
            return true;
        }
        catch (ApiException ex) when (SessionAccess.IsNotFound(ex))
        {
            return false;
        }
    }

    private async Task CountAsync(Guid id, CancellationToken ct)
    {
        var all = await SessionAccess.AllAsync(api, HttpContext.Current(), id, ct);
        CountIsLowerBound = all is null;
        var now = time.GetUtcNow();
        Count = all?.Count(s => SessionAccess.State(s, now) == "active") ?? SessionAccess.MaxPages * 200;
    }
}
