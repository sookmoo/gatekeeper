using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients;

public class DeleteModel(GatekeeperApi api, ILogger<DeleteModel> log) : PageModel
{
    public ClientDto Target { get; private set; } = null!;
    public string AppName { get; private set; } = "(unknown)";
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        try
        {
            await api.DeleteClientAsync(HttpContext.Current(), id, ct);
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Deleting a client was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            Error = "The client could not be deleted.";
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetClientAsync(session, id, ct);
            var names = await Users.UserAccess.AppNamesAsync(api, session, [Target.AppId], ct);
            if (names.TryGetValue(Target.AppId, out var n)) AppName = n;
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
