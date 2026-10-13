using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications;

public class IndexModel(GatekeeperApi api) : PageModel
{
    private const int PageSize = 25;

    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["created"] = "Application created.",
        ["renamed"] = "Application renamed.",
        ["deleted"] = "Application deleted.",
    };

    public List<AppDto> Items { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Done { get; private set; }

    public async Task<IActionResult> OnGetAsync(string? cursor, string? done, CancellationToken ct)
    {
        Done = done is not null && Messages.TryGetValue(done, out var message) ? message : null;
        try
        {
            var page = await api.ListAppsAsync(HttpContext.Current(), cursor, PageSize, ct);
            Items = page.Items;
            NextCursor = page.NextCursor;
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == System.Net.HttpStatusCode.BadRequest)
        {
            return RedirectToPage(); // an edited or outdated cursor: back to the first page
        }
        return Page();
    }
}
