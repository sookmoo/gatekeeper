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

    public async Task OnGetAsync(string? cursor, string? done, CancellationToken ct)
    {
        Done = done is not null && Messages.TryGetValue(done, out var message) ? message : null;
        var page = await api.ListAppsAsync(HttpContext.Current(), cursor, PageSize, ct);
        Items = page.Items;
        NextCursor = page.NextCursor;
    }
}
