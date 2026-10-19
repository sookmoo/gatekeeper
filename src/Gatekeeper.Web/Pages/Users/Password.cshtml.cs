using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users;

public class PasswordModel(GatekeeperApi api, WebSessions sessions) : PageModel
{
    // Never rendered back, never logged: the page has no value attribute for these and the texts below are fixed.
    [BindProperty] public string? Password { get; set; }
    [BindProperty] public string? Confirm { get; set; }

    public UserDto Target { get; private set; } = null!;
    public string? Error { get; private set; }
    public string? Done { get; private set; }
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Target.Id;

    public async Task<IActionResult> OnGetAsync(Guid id, string? done, CancellationToken ct)
    {
        Done = done == "set" ? "Password set. The user's sign-in sessions were ended; access tokens already issued stay valid until they expire (up to 15 minutes) unless the receiving application checks with the API." : null;
        return await LoadAsync(id, ct) ? Page() : NotFound();
    }

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        var password = Password;
        var confirm = Confirm;
        Password = null; // nothing of it may reach the page again
        Confirm = null;
        if (string.IsNullOrEmpty(password)) return Fail(HttpStatusCode.BadRequest, "Enter a password.");
        if (!string.Equals(password, confirm, StringComparison.Ordinal)) return Fail(HttpStatusCode.BadRequest, "The two passwords are not the same.");
        try
        {
            var self = IsSelf;
            await api.SetPasswordAsync(HttpContext.Current(), id, password, ct);
            // A new password ends the user's sessions, this one included when it is their own: go to the sign-in page, not an error.
            if (self) return Redirect(await UserAccess.EndOwnSessionAsync(api, sessions, HttpContext, ct));
            return RedirectToPage(new { id, done = "set" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            // A fixed text: the API's wording is not shown here.
            return Fail(ex.Status, ex.Status == HttpStatusCode.BadRequest ? UserAccess.PasswordRulesText : "The password could not be set.");
        }
    }

    private IActionResult Fail(HttpStatusCode status, string error)
    {
        Error = error;
        Response.StatusCode = (int)status;
        return Page();
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
