using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients;

public class DeleteModel(GatekeeperApi api, ILogger<DeleteModel> log) : PageModel
{
    /// <summary>The version the hidden field carries: the current one, except after a refusal other than 412/400, which keeps the one that was posted.</summary>
    public long HiddenVersion { get; private set; }
    public ClientDto Target { get; private set; } = null!;
    public string AppName { get; private set; } = "(unknown)";
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        // Never an unconditional delete: without a usable version nothing is sent.
        if (!FormVersion.TryRead(Request, out var version))
        {
            Error = FormVersion.MissingText;
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Page();
        }
        try
        {
            await api.DeleteClientAsync(HttpContext.Current(), id, version, ct);
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Deleting a client was refused as stale: {Detail}", Users.UserAccess.ForLog(ex.Message));
            if (!await LoadAsync(id, ct)) return NotFound(); // the page now shows the current values and version
            Error = FormVersion.ChangedText;
            Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return Page();
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Deleting a client was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            Error = "The client could not be deleted.";
            HiddenVersion = version; // a retry must still pass the guard against the data as it was read
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
            HiddenVersion = Target.Version;
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
