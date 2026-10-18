using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users;

public class CreateModel(GatekeeperApi api) : PageModel
{
    [BindProperty] public string? Username { get; set; }
    [BindProperty] public string? Email { get; set; }
    [BindProperty] public string? DisplayName { get; set; }
    [BindProperty] public string? Kind { get; set; } = "person";
    [BindProperty] public string? Expiry { get; set; }
    public string? Error { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        if (!UserForm.IsKind(Kind)) return Fail(UserForm.KindText);
        if (!UserForm.TryParseExpiry(Expiry, out var expiresAt)) return Fail(UserForm.ExpiryText);
        try
        {
            // The expiry belongs to test users only; empty means the API's default lifetime.
            await api.CreateUserAsync(HttpContext.Current(), Username?.Trim() ?? "", Email?.Trim() ?? "", DisplayName?.Trim() ?? "", Kind!, Kind == "test" ? expiresAt : null, ct);
            return RedirectToPage("Index", new { done = "created" });
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized && ex.Status != HttpStatusCode.NotFound)
        {
            return Fail(ex.Message);
        }
    }

    private IActionResult Fail(string error)
    {
        Error = error;
        return Page();
    }
}
