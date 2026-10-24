using System.Net;
using Gatekeeper.Web.Pages.Users;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Account;

/// <summary>
/// The signed-in user changes their own password. None of the three values is ever rendered back, logged or put in a URL, and every
/// message below is a fixed text (the API's wording is not shown). A wrong current password is a form error, not a sign-out: this web
/// session stays valid, also after a success (the API keeps the session the request came from and ends the others).
/// </summary>
public class PasswordModel(GatekeeperApi api) : PageModel
{
    public const string WrongCurrentText = "The current password is incorrect.";
    public const string ThrottledText = "Too many attempts. Try again later.";
    public const string MismatchText = "The two new passwords are not the same.";
    public const string SameText = "The new password must differ from the current one.";
    public const string MissingText = "Enter your current password and a new password.";
    public const string FailedText = "The password could not be changed.";

    // Bound by hand, so nothing is ever echoed into the page (the view has no value attributes for them).
    [BindProperty] public string? Current { get; set; }
    [BindProperty] public string? New { get; set; }
    [BindProperty] public string? Confirm { get; set; }

    public string? Error { get; private set; }

    public IActionResult OnGet() => Page();

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var current = Current;
        var replacement = New;
        var confirm = Confirm;
        Current = New = Confirm = null; // nothing of them may reach the page again
        if (string.IsNullOrEmpty(current) || string.IsNullOrEmpty(replacement)) return Fail(HttpStatusCode.BadRequest, MissingText);
        if (!string.Equals(replacement, confirm, StringComparison.Ordinal)) return Fail(HttpStatusCode.BadRequest, MismatchText);
        if (string.Equals(current, replacement, StringComparison.Ordinal)) return Fail(HttpStatusCode.BadRequest, SameText);
        try
        {
            await api.ChangeOwnPasswordAsync(HttpContext.Current(), current, replacement, ct);
            return RedirectToPage("/Account/Index", new { done = "password" });
        }
        catch (ApiException ex) when (ex.Code == ApiException.WrongCurrentPassword)
        {
            return Fail(HttpStatusCode.BadRequest, WrongCurrentText);
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.TooManyRequests)
        {
            return Fail(HttpStatusCode.TooManyRequests, ThrottledText);
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            return Fail(ex.Status, ex.Status == HttpStatusCode.BadRequest ? UserAccess.PasswordRulesText : FailedText);
        }
    }

    private IActionResult Fail(HttpStatusCode status, string error)
    {
        Error = error;
        Response.StatusCode = (int)status;
        return Page();
    }
}
