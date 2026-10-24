using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages;

public class LogoutModel(GatekeeperApi api, WebSessions sessions) : PageModel
{
    public IActionResult OnGet() => RedirectToPage(User.IsInRole(WebSession.AdminRole) ? "/Applications/Index" : "/Account/Index");

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var session = HttpContext.Current();
        await api.LogoutAsync(session, ct); // ends the session on the API too (best effort)
        sessions.Remove(session.Id);
        SessionCookie.Clear(HttpContext);
        return RedirectToPage("/Login");
    }
}
