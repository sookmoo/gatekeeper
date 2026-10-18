using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications.Roles;

public class DeleteModel(GatekeeperApi api) : PageModel
{
    public AppDto App { get; private set; } = null!;
    public RoleDto Role { get; private set; } = null!;
    public bool ReadOnly { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid appId, Guid id, CancellationToken ct) =>
        await LoadAsync(appId, id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid appId, Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(appId, id, ct)) return NotFound();
        try
        {
            await api.DeleteRoleAsync(HttpContext.Current(), id, ct);
            return RedirectToPage("Index", new { appId, done = "deleted" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = Refusal(ex);
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
