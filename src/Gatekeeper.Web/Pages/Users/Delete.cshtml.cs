using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users;

public class DeleteModel(GatekeeperApi api, WebSessions sessions, ILogger<DeleteModel> log) : PageModel
{
    /// <summary>The version the hidden field carries: the current one, except after a refusal other than 412/400, which keeps the one that was posted.</summary>
    public long HiddenVersion { get; private set; }
    public UserDto Target { get; private set; } = null!;
    public string? Error { get; private set; }
    /// <summary>The target is the signed-in administrator's own account.</summary>
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Target.Id;

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        // Never an unconditional delete: without a usable version nothing is sent.
        if (!FormVersion.TryRead(Request, out var version))
        {
            Error = FormVersion.MissingText;
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Page();
        }
        try
        {
            var self = IsSelf;
            await api.DeleteUserAsync(HttpContext.Current(), id, version, ct);
            if (self) return await EndOwnSessionAsync(ct);
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Deleting a user was refused as stale: {Detail}", UserAccess.ForLog(ex.Message));
            if (!await LoadAsync(id, ct)) return NotFound(); // the page now shows the current values and version
            Error = FormVersion.ChangedText;
            Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return Page();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = ex.Message;
            HiddenVersion = version; // a retry must still pass the guard against the data as it was read
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
            HiddenVersion = Target.Version;
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
