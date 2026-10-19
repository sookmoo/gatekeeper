using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users;

public class DeleteModel(GatekeeperApi api, WebSessions sessions) : PageModel
{
    public UserDto Target { get; private set; } = null!;
    public string? Error { get; private set; }
    /// <summary>The target is the signed-in administrator's own account.</summary>
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Target.Id;

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        try
        {
            var self = IsSelf;
            await api.DeleteUserAsync(HttpContext.Current(), id, ct);
            if (self) return await EndOwnSessionAsync(ct);
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = ex.Message;
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    // The account is gone: end the web session now rather than when the API's admin check next notices.
    private async Task<IActionResult> EndOwnSessionAsync(CancellationToken ct)
    {
        var session = HttpContext.Current();
        await api.LogoutAsync(session, ct); // revokes the refresh session too (best effort)
        sessions.Remove(session.Id);
        SessionCookie.Clear(HttpContext);
        return Redirect("/Login?ended=1");
    }

    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            Target = await api.GetUserAsync(HttpContext.Current(), id, ct);
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
