using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications;

public class CreateModel(GatekeeperApi api) : PageModel
{
    [BindProperty] public string? Name { get; set; }
    public string? Error { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        try
        {
            await api.CreateAppAsync(HttpContext.Current(), Name?.Trim() ?? "", ct);
            return RedirectToPage("Index", new { done = "created" });
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != System.Net.HttpStatusCode.Unauthorized)
        {
            Error = ex.Message; // validation or conflict, as the API words it
            return Page();
        }
    }
}
