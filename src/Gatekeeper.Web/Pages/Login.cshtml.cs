using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages;

public class LoginModel(GatekeeperApi api, FailureThrottle throttle, WebSessions sessions) : PageModel
{
    [BindProperty] public string? Username { get; set; }
    [BindProperty] public string? Password { get; set; }
    public string? Error { get; private set; }
    public bool Ended => Request.Query.ContainsKey("ended");

    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true ? RedirectToPage("/Applications/Index") : Page();

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var address = (HttpContext.Connection.RemoteIpAddress ?? IPAddress.None).ToString();
        if (throttle.IsBlocked(address, out var wait))
        {
            Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
            Response.StatusCode = StatusCodes.Status429TooManyRequests;
            Error = "Too many failed attempts. Try again later.";
            return Page();
        }
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrEmpty(Password) || Username.Length > 256 || Password.Length > 1024)
        {
            Error = "Enter a username and a password.";
            return Page();
        }

        try
        {
            var session = await api.LoginAsync(Username.Trim(), Password, ct);
            throttle.RecordSuccess(address);
            // A fresh id at every sign-in: whatever cookie the browser came with is never reused.
            sessions.Remove(Request.Cookies[SessionAuthHandler.CookieName]);
            SessionCookie.Set(HttpContext, session);
            return RedirectToPage("/Applications/Index");
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
        {
            throttle.RecordFailure(address);
            // One message for a wrong password, an unknown user and a user without administrator access.
            Error = "Invalid credentials, or not an administrator.";
            Password = null;
            return Page();
        }
        catch (ApiException ex)
        {
            Error = ex.Message;
            Password = null;
            return Page();
        }
    }
}
