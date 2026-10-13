using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications;

public class DeleteModel(GatekeeperApi api) : PageModel
{
    public string? Name { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct)
    {
        try
        {
            Name = (await api.GetAppAsync(HttpContext.Current(), id, ct)).Name;
            return Page();
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
    }

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        try
        {
            await api.DeleteAppAsync(HttpContext.Current(), id, ct);
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Name = (await api.GetAppAsync(HttpContext.Current(), id, ct)).Name;
            Error = ex.Message;
            return Page();
        }
    }
}
