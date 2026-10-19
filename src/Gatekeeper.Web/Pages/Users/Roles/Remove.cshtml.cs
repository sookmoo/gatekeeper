using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users.Roles;

public class RemoveModel(GatekeeperApi api, WebSessions sessions, ILogger<RemoveModel> log) : PageModel
{
    private const int MaxPages = 50;

    public UserDto Target { get; private set; } = null!;
    public RoleDto Role { get; private set; } = null!;
    public AppDto App { get; private set; } = null!;
    public string? Error { get; private set; }
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Target.Id;
    /// <summary>The role is the one that grants access to this UI.</summary>
    public bool IsAdminRole => GatekeeperApi.IsAdminRole(App, Role);

    public async Task<IActionResult> OnGetAsync(Guid id, Guid roleId, CancellationToken ct) =>
        await LoadAsync(id, roleId, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, Guid roleId, CancellationToken ct)
    {
        if (!await LoadAsync(id, roleId, ct)) return NotFound();
        try
        {
            var endsOwnAccess = IsSelf && IsAdminRole;
            await api.RevokeUserRoleAsync(HttpContext.Current(), id, roleId, ct);
            // Without the admin role the UI session is worthless: end it now rather than when the API's admin check notices.
            if (endsOwnAccess) return Redirect(await UserAccess.EndOwnSessionAsync(api, sessions, HttpContext, ct));
            return RedirectToPage("Index", new { id, done = "removed" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Removing a role was refused with status {Status}: {Detail}", (int)ex.Status, UserAccess.ForLog(ex.Message));
            Error = UserAccess.RoleRefusalText(ex);
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    // False unless the user exists, the role exists and the user holds it (a role id that is not theirs is a 404, never acted on).
    private async Task<bool> LoadAsync(Guid id, Guid roleId, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetUserAsync(session, id, ct);
            Role = await api.GetRoleAsync(session, roleId, ct);
            App = await api.GetAppAsync(session, Role.AppId, ct);
            string? cursor = null;
            // Bounded: a user with more roles than this is refused rather than walked without end.
            for (var pages = 0; pages < MaxPages; pages++)
            {
                var page = await api.ListUserRolesAsync(session, id, Role.AppId, cursor, 200, ct);
                if (page.Items.Any(r => r.Id == roleId)) return true;
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
