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
            HttpContext.Current().InvalidateAppList(); // the clients pages re-read the application list
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            HttpContext.Current().InvalidateAppList(); // it is gone (or renamed elsewhere): do not keep a stale list
            return NotFound();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = ex.Message;
            try
            {
                Name = (await api.GetAppAsync(HttpContext.Current(), id, ct)).Name;
            }
            catch (ApiException again) when (again.Status == HttpStatusCode.NotFound)
            {
                return NotFound(); // it vanished in the meantime
            }
            return Page();
        }
    }
}
