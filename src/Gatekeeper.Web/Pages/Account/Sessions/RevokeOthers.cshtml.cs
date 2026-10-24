using Gatekeeper.Web.Pages.Users;
using Gatekeeper.Web.Pages.Users.Sessions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Account.Sessions;

/// <summary>Confirmation for ending all of the signed-in user's other sessions. The current one stays; it ends by signing out.</summary>
public class RevokeOthersModel(GatekeeperApi api, TimeProvider time, ILogger<RevokeOthersModel> log) : PageModel
{
    public int Count { get; private set; }
    public string? Error { get; private set; }
    public TimeSpan? Lifetime => HttpContext.Current().AccessLifetime;

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        await CountAsync(ct);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        try
        {
            // The API's own answer says how many it ended.
            var revoked = await api.RevokeOtherOwnSessionsAsync(HttpContext.Current(), ct);
            return RedirectToPage("/Account/Index", new { done = "revokedothers", n = revoked });
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Revoking other own sessions was refused with status {Status}: {Detail}", (int)ex.Status, UserAccess.ForLog(ex.Message));
            Error = SessionAccess.RefusalText;
            await CountAsync(ct);
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    private async Task CountAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        Count = (await api.ListOwnSessionsAsync(HttpContext.Current(), ct)).Count(s => !s.Current && IndexModel.SessionState(s, now) == "active");
    }
}
