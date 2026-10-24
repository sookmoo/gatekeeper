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

    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true ? RedirectToPage(User.IsInRole(WebSession.AdminRole) ? "/Applications/Index" : "/Account/Index") : Page();

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var address = (HttpContext.Connection.RemoteIpAddress ?? IPAddress.None).ToString();
        if (throttle.IsBlocked(address, Username, out var wait))
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
            // A fresh id at every sign-in: whatever cookie the browser came with is never reused (its session ends once this one succeeded).
            var came = sessions.Find(SessionCookie.Read(HttpContext));
            var session = await api.LoginAsync(Username.Trim(), Password, ct, came);
            throttle.RecordSuccess(address, Username);
            SessionCookie.Set(HttpContext, session);
            // Administrators land on the management pages, everyone else on their own account.
            return RedirectToPage(session.IsAdmin ? "/Applications/Index" : "/Account/Index");
        }
        catch (WebSessionLimitException)
        {
            // Nobody else is signed out to make room: refuse and say so.
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            Response.Headers.RetryAfter = "60";
            Error = "Too many people are signed in right now. Try again later.";
            Password = null;
            return Page();
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
        {
            throttle.RecordFailure(address, Username);
            // One message for a wrong password, an unknown user and a disabled or expired account.
            Error = "Invalid credentials.";
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
