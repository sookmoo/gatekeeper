using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users.Roles;

/// <summary>Adding a role without JavaScript takes two steps: choose an application (GET form), then choose one of its roles (POST form).</summary>
public class AddModel(GatekeeperApi api, ILogger<AddModel> log) : PageModel
{
    private const int PageSize = 100;

    /// <summary>The application chosen in step 1 (query string on GET, hidden field on POST).</summary>
    [BindProperty(SupportsGet = true, Name = "app")] public Guid? AppId { get; set; }
    [FromForm, BindProperty] public Guid? RoleId { get; set; }
    [BindProperty(SupportsGet = true)] public string? Cursor { get; set; }

    public UserDto Target { get; private set; } = null!;
    public AppDto? App { get; private set; }
    public List<AppDto> Apps { get; private set; } = [];
    public List<RoleDto> Roles { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public bool Reserved { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct) =>
        await LoadAsync(id, ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        Cursor = null;
        // On POST the application comes from the form only, like the role: a query string value is ignored.
        AppId = Guid.TryParse(Request.Form["app"].FirstOrDefault(), out var formApp) ? formApp : null;
        if (!await LoadAsync(id, ct)) return NotFound();
        if (App is null) return NotFound();
        if (RoleId is not { } roleId) return Fail(HttpStatusCode.BadRequest, "Choose a role.");
        try
        {
            var session = HttpContext.Current();
            // The role must belong to the chosen application: a role id of another application is not what the admin was shown.
            var role = await api.GetRoleAsync(session, roleId, ct);
            if (role.AppId != App.Id) return NotFound();
            await api.AssignUserRoleAsync(session, id, roleId, ct);
            return RedirectToPage("Index", new { id, done = "added" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Adding a role was refused with status {Status}: {Detail}", (int)ex.Status, UserAccess.ForLog(ex.Message));
            return Fail(ex.Status, UserAccess.RoleRefusalText(ex));
        }
    }

    private IActionResult Fail(HttpStatusCode status, string error)
    {
        Error = error;
        Response.StatusCode = (int)status;
        return Page();
    }

    // False when the user or the chosen application does not exist.
    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetUserAsync(session, id, ct);
            if (AppId is not { } appId)
            {
                var apps = await api.ListAppsAsync(session, Cursor, PageSize, ct);
                Apps = apps.Items;
                NextCursor = apps.NextCursor;
                return true;
            }
            App = await api.GetAppAsync(session, appId, ct);
            Reserved = GatekeeperApi.IsReserved(App);
            var roles = await api.ListRolesAsync(session, appId, Cursor, PageSize, ct);
            // The reserved application offers only its admin role (the API refuses any other).
            Roles = Reserved ? roles.Items.Where(r => GatekeeperApi.IsAdminRole(App, r)).ToList() : roles.Items;
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
            return await LoadAsync(id, ct);
        }
    }

    public string NextHref() =>
        $"/Users/{Target.Id}/Roles/Add?" + (App is not null ? $"app={App.Id}&" : "") + "cursor=" + Uri.EscapeDataString(NextCursor!);
}
