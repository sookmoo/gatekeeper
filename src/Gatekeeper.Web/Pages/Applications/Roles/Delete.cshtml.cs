using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications.Roles;

public class DeleteModel(GatekeeperApi api, ILogger<DeleteModel> log) : PageModel
{
    public AppDto App { get; private set; } = null!;
    /// <summary>The version the hidden field carries: the current one, except after a refusal other than 412/400, which keeps the one that was posted.</summary>
    public long HiddenVersion { get; private set; }
    public RoleDto Role { get; private set; } = null!;
    public bool ReadOnly { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid appId, Guid id, CancellationToken ct) =>
        await LoadAsync(appId, id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid appId, Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(appId, id, ct)) return NotFound();
        // Never an unconditional delete: without a usable version nothing is sent.
        if (!FormVersion.TryRead(Request, out var version))
        {
            Error = FormVersion.MissingText;
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Page();
        }
        try
        {
            await api.DeleteRoleAsync(HttpContext.Current(), id, version, ct);
            return RedirectToPage("Index", new { appId, done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Deleting a role was refused as stale: {Detail}", Users.UserAccess.ForLog(ex.Message));
            if (!await LoadAsync(appId, id, ct)) return NotFound(); // the page now shows the current values and version
            Error = FormVersion.ChangedText;
            Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return Page();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = Refusal(ex);
            HiddenVersion = version; // a retry must still pass the guard against the data as it was read
            return Page();
        }
    }

    private string Refusal(ApiException ex)
    {
        if (!ReadOnly || ex.Status != HttpStatusCode.Conflict) return ex.Message;
        Response.StatusCode = StatusCodes.Status409Conflict;
        return CreateModel.ReservedText;
    }

    private async Task<bool> LoadAsync(Guid appId, Guid id, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Role = await api.GetRoleAsync(session, id, ct);
            HiddenVersion = Role.Version;
            // Ownership check: relies on roles never moving between applications, so the app in the URL is the role's app.
            if (Role.AppId != appId) return false;
            App = await api.GetAppAsync(session, appId, ct);
            ReadOnly = GatekeeperApi.IsReserved(App);
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
