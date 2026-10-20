using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients.Roles;

public class RemoveModel(GatekeeperApi api, ILogger<RemoveModel> log) : PageModel
{
    private const int MaxPages = 50;

    public ClientDto Target { get; private set; } = null!;
    public RoleDto Role { get; private set; } = null!;
    public string AppName { get; private set; } = "(unknown)";
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, Guid roleId, CancellationToken ct) =>
        await LoadAsync(id, roleId, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, Guid roleId, CancellationToken ct)
    {
        if (!await LoadAsync(id, roleId, ct)) return NotFound();
        try
        {
            await api.RevokeClientRoleAsync(HttpContext.Current(), id, roleId, ct);
            return RedirectToPage("Index", new { id, done = "removed" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Removing a client role was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            Error = ClientAccess.RoleRefusalText(ex);
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    // False unless the client exists and holds the role (a role id that is not its own is a 404, never acted on).
    private async Task<bool> LoadAsync(Guid id, Guid roleId, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetClientAsync(session, id, ct);
            string? cursor = null;
            // Bounded: a client with more roles than this is refused rather than walked without end.
            for (var pages = 0; pages < MaxPages; pages++)
            {
                var page = await api.ListClientRolesAsync(session, id, cursor, 200, ct);
                if (page.Items.FirstOrDefault(r => r.Id == roleId) is { } role)
                {
                    Role = role;
                    var names = await Users.UserAccess.AppNamesAsync(api, session, [Target.AppId], ct);
                    if (names.TryGetValue(Target.AppId, out var n)) AppName = n;
                    return true;
                }
                cursor = page.NextCursor;
                if (cursor is null) return false;
            }
            return false; // fail closed
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
