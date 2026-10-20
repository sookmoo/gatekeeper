using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications;

public class EditModel(GatekeeperApi api) : PageModel
{
    [BindProperty] public string? Name { get; set; }
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
            await api.RenameAppAsync(HttpContext.Current(), id, Name?.Trim() ?? "", ct);
            HttpContext.Current().InvalidateAppList(); // the clients pages re-read the application list
            return RedirectToPage("Index", new { done = "renamed" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            HttpContext.Current().InvalidateAppList(); // it is gone (or renamed elsewhere): do not keep a stale list
            return NotFound();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = ex.Message;
            return Page();
        }
    }
}
