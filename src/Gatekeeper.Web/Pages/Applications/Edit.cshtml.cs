using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications;

public class EditModel(GatekeeperApi api, ILogger<EditModel> log) : PageModel
{
    [BindProperty] public string? Name { get; set; }
    /// <summary>The version the hidden field carries: the one the form was opened with, or the fresh one after a refusal that re-reads the application.</summary>
    public long HiddenVersion { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct)
    {
        try
        {
            var app = await api.GetAppAsync(HttpContext.Current(), id, ct);
            Name = app.Name;
            HiddenVersion = app.Version;
            return Page();
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
    }

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        // Never an unconditional write: without a usable version nothing is sent and the form is shown again with the current name.
        if (!FormVersion.TryRead(Request, out var version)) return await ShowCurrentAsync(id, FormVersion.MissingText, StatusCodes.Status400BadRequest, ct);
        HiddenVersion = version;
        try
        {
            await api.RenameAppAsync(HttpContext.Current(), id, Name?.Trim() ?? "", version, ct);
            HttpContext.Current().InvalidateAppList(); // the clients pages re-read the application list
            return RedirectToPage("Index", new { done = "renamed" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            HttpContext.Current().InvalidateAppList(); // it is gone (or renamed elsewhere): do not keep a stale list
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Renaming an application was refused as stale: {Detail}", Users.UserAccess.ForLog(ex.Message));
            HttpContext.Current().InvalidateAppList(); // it was changed elsewhere
            return await ShowCurrentAsync(id, FormVersion.ChangedText, StatusCodes.Status412PreconditionFailed, ct);
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = ex.Message;
            return Page();
        }
    }

    // Shows the application as the API holds it now, with its version, instead of what was typed.
    private async Task<IActionResult> ShowCurrentAsync(Guid id, string error, int status, CancellationToken ct)
    {
        try
        {
            var app = await api.GetAppAsync(HttpContext.Current(), id, ct);
            Name = app.Name;
            HiddenVersion = app.Version;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            HttpContext.Current().InvalidateAppList();
            return NotFound();
        }
        Error = error;
        Response.StatusCode = status;
        return Page();
    }
}
