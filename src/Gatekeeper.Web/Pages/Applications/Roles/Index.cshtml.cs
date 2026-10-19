using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications.Roles;

public class IndexModel(GatekeeperApi api) : PageModel
{
    private const int PageSize = 25;

    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["created"] = "Role created.",
        ["updated"] = "Role updated.",
        ["deleted"] = "Role deleted.",
    };

    public AppDto App { get; private set; } = null!;
    public bool ReadOnly { get; private set; }
    public List<RoleDto> Items { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Done { get; private set; }

    // The list has no form: a crafted POST is a plain 404, not a page without data.
    public IActionResult OnPost() => NotFound();

    public async Task<IActionResult> OnGetAsync(Guid appId, string? cursor, string? done, CancellationToken ct)
    {
        Done = done is not null && Messages.TryGetValue(done, out var message) ? message : null;
        try
        {
            var session = HttpContext.Current();
            App = await api.GetAppAsync(session, appId, ct);
            ReadOnly = GatekeeperApi.IsReserved(App);
            var page = await api.ListRolesAsync(session, appId, cursor, PageSize, ct);
            Items = page.Items;
            NextCursor = page.NextCursor;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == HttpStatusCode.BadRequest)
        {
            return RedirectToPage(new { appId }); // an edited or outdated cursor: back to the first page
        }
        return Page();
    }
}
