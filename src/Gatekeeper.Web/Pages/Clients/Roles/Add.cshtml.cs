using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients.Roles;

/// <summary>Adds a role of the client's own application in one step. The choices are that application's roles the client does not hold yet.</summary>
public class AddModel(GatekeeperApi api, ILogger<AddModel> log) : PageModel
{
    private const int PageSize = 100;

    [FromForm, BindProperty] public Guid? RoleId { get; set; }
    [BindProperty(SupportsGet = true)] public string? Cursor { get; set; }

    public ClientDto Target { get; private set; } = null!;
    public string AppName { get; private set; } = "(unknown)";
    public bool Reserved { get; private set; }
    public List<RoleDto> Roles { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        Cursor = null;
        try
        {
            // Only what assigning needs: the client and its application (for the page shown on failure), not the role lists.
            if (!await LoadAsync(id, false, ct)) return NotFound();
            if (RoleId is not { } roleId) return Fail(HttpStatusCode.BadRequest, "Choose a role.");
            // The role id is sent as given: a role of another application is refused by the API and that refusal is shown.
            await api.AssignClientRoleAsync(HttpContext.Current(), id, roleId, ct);
            return RedirectToPage("Index", new { id, done = "added" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Adding a client role was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            return Fail(ex.Status, ClientAccess.RoleRefusalText(ex));
        }
    }

    private Task<bool> LoadAsync(Guid id, CancellationToken ct) => LoadAsync(id, true, ct);

    private IActionResult Fail(HttpStatusCode status, string error)
    {
        Error = error;
        Response.StatusCode = (int)status;
        return Page();
    }

    // False when the client does not exist.
    private async Task<bool> LoadAsync(Guid id, bool withRoles, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetClientAsync(session, id, ct);
            var app = await api.GetAppAsync(session, Target.AppId, ct);
            AppName = app.Name;
            Reserved = GatekeeperApi.IsReserved(app);
            if (Reserved || !withRoles) return true;
            var held = await ClientAccess.HeldRoleIdsAsync(api, session, id, ct);
            var roles = await api.ListRolesAsync(session, Target.AppId, Cursor, PageSize, ct);
            Roles = roles.Items.Where(r => !held.Contains(r.Id)).ToList();
            NextCursor = roles.NextCursor;
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
        catch (ApiException ex) when (Cursor is not null && ex.Status == HttpStatusCode.BadRequest)
        {
            Cursor = null; // an edited or outdated cursor: the first page
            return await LoadAsync(id, withRoles, ct);
        }
    }

    public string NextHref() =>
        $"/Clients/{Target.Id}/Roles/Add?cursor=" + Uri.EscapeDataString(NextCursor!);
}
