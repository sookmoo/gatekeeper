using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users.Roles;

public record UserRoleRow(RoleDto Role, string? AppName, bool IsAdmin);

public class IndexModel(GatekeeperApi api) : PageModel
{
    private const int PageSize = 25;

    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["added"] = "Role added.",
        ["removed"] = "Role removed.",
    };

    public UserDto Target { get; private set; } = null!;
    public List<UserRoleRow> Items { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Done { get; private set; }
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Target.Id;

    // The list has no form: a crafted POST is a plain 404, not a page without data.
    public IActionResult OnPost() => NotFound();

    public async Task<IActionResult> OnGetAsync(Guid id, string? cursor, string? done, CancellationToken ct)
    {
        Done = done is not null && Messages.TryGetValue(done, out var message) ? message : null;
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetUserAsync(session, id, ct);
            var page = await api.ListUserRolesAsync(session, id, null, cursor, PageSize, ct);
            NextCursor = page.NextCursor;
            // The API names each role's application, so no per-application GET is needed.
            Items = page.Items.Select(r =>
            {
                var app = string.IsNullOrEmpty(r.AppName) ? null : r.AppName;
                var admin = app is not null && GatekeeperApi.IsAdminRole(new AppDto(r.AppId, app), r);
                return new UserRoleRow(r, app, admin);
            }).ToList();
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == HttpStatusCode.BadRequest)
        {
            return RedirectToPage(new { id }); // an edited or outdated cursor: back to the first page
        }
        return Page();
    }
}
