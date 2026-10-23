using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications.Roles;

public class EditModel(GatekeeperApi api, ILogger<EditModel> log) : PageModel
{
    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Description { get; set; }
    /// <summary>The version the hidden field carries: the one the form was opened with, or the fresh one after a refusal that re-reads the role.</summary>
    public long HiddenVersion { get; private set; }
    public AppDto App { get; private set; } = null!;
    public bool ReadOnly { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid appId, Guid id, CancellationToken ct)
    {
        var role = await LoadAsync(appId, id, ct);
        if (role is null) return NotFound();
        Name = role.Name;
        Description = role.Description;
        HiddenVersion = role.Version;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid appId, Guid id, CancellationToken ct)
    {
        var current = await LoadAsync(appId, id, ct);
        if (current is null) return NotFound();
        // Never an unconditional write: without a usable version nothing is sent and the form is shown again with the current values.
        if (!FormVersion.TryRead(Request, out var version)) return ShowCurrent(current, FormVersion.MissingText, StatusCodes.Status400BadRequest);
        HiddenVersion = version;
        try
        {
            await api.UpdateRoleAsync(HttpContext.Current(), id, Name?.Trim() ?? "", Description?.Trim() ?? "", version, ct);
            return RedirectToPage("Index", new { appId, done = "updated" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Updating a role was refused as stale: {Detail}", Users.UserAccess.ForLog(ex.Message));
            var fresh = await LoadAsync(appId, id, ct);
            return fresh is null ? NotFound() : ShowCurrent(fresh, FormVersion.ChangedText, StatusCodes.Status412PreconditionFailed);
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = Refusal(ex);
            return Page();
        }
    }

    // Shows the role as the API holds it now, with its version, instead of what was typed.
    private IActionResult ShowCurrent(RoleDto role, string error, int status)
    {
        Name = role.Name;
        Description = role.Description;
        HiddenVersion = role.Version;
        Error = error;
        Response.StatusCode = status;
        return Page();
    }

    private string Refusal(ApiException ex)
    {
        if (!ReadOnly || ex.Status != HttpStatusCode.Conflict) return ex.Message;
        Response.StatusCode = StatusCodes.Status409Conflict;
        return CreateModel.ReservedText;
    }

    // The role, or null when the role or the application is unknown or the role belongs to another application.
    private async Task<RoleDto?> LoadAsync(Guid appId, Guid id, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            var role = await api.GetRoleAsync(session, id, ct);
            // Ownership check: relies on roles never moving between applications, so the app in the URL is the role's app.
            if (role.AppId != appId) return null;
            App = await api.GetAppAsync(session, appId, ct);
            ReadOnly = GatekeeperApi.IsReserved(App);
            return role;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return null;
        }
    }
}
