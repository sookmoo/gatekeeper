using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications;

public class DeleteModel(GatekeeperApi api, ILogger<DeleteModel> log) : PageModel
{
    public string? Name { get; private set; }
    /// <summary>The version of the application as last read; the hidden field carries it.</summary>
    public long HiddenVersion { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        // Never an unconditional delete: without a usable version nothing is sent.
        if (!FormVersion.TryRead(Request, out var version))
            return await ShowCurrentAsync(id, FormVersion.MissingText, StatusCodes.Status400BadRequest, ct);
        try
        {
            await api.DeleteAppAsync(HttpContext.Current(), id, version, ct);
            HttpContext.Current().InvalidateAppList(); // the clients pages re-read the application list
            return RedirectToPage("Index", new { done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            HttpContext.Current().InvalidateAppList(); // it is gone (or renamed elsewhere): do not keep a stale list
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Deleting an application was refused as stale: {Detail}", Users.UserAccess.ForLog(ex.Message));
            HttpContext.Current().InvalidateAppList(); // it was changed elsewhere
            return await ShowCurrentAsync(id, FormVersion.ChangedText, StatusCodes.Status412PreconditionFailed, ct);
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            var shown = await ShowCurrentAsync(id, ex.Message, null, ct);
            HiddenVersion = version; // a retry must still pass the guard against the data as it was read
            return shown;
        }
    }

    private async Task<IActionResult> ShowCurrentAsync(Guid id, string error, int? status, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct))
        {
            HttpContext.Current().InvalidateAppList();
            return NotFound(); // it vanished in the meantime
        }
        Error = error;
        if (status is { } s) Response.StatusCode = s;
        return Page();
    }

    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            var app = await api.GetAppAsync(HttpContext.Current(), id, ct);
            Name = app.Name;
            HiddenVersion = app.Version;
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
