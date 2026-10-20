using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients;

public class IndexModel(GatekeeperApi api, TimeProvider time, ILogger<IndexModel> log) : PageModel
{
    private const int PageSize = 25;

    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["updated"] = "Client updated.",
        ["deleted"] = "Client deleted.",
    };

    private Dictionary<Guid, string> _names = [];

    public List<ClientDto> Items { get; private set; } = [];
    public List<AppDto> Apps { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Error { get; private set; }
    public string? Done { get; private set; }
    /// <summary>The application filter in effect (a valid id; anything else is ignored).</summary>
    public Guid? AppFilter { get; private set; }

    public string AppName(ClientDto c) => _names.TryGetValue(c.AppId, out var n) ? n : "(unknown)";

    // The list has no form: a crafted POST is a plain 404, not a page without data.
    public IActionResult OnPost() => NotFound();

    public async Task<IActionResult> OnGetAsync(string? app, string? cursor, string? done, CancellationToken ct)
    {
        Done = done is not null && Messages.TryGetValue(done, out var message) ? message : null;
        AppFilter = Guid.TryParse(app, out var appId) ? appId : null;
        var session = HttpContext.Current();
        try
        {
            // The application list (filter and names) is reused for a few seconds; a filter on an unknown application reads it afresh.
            var apps = await ClientAccess.CachedAppsAsync(api, session, time, AppFilter, ct);
            Apps = apps.Choices;
            _names = new Dictionary<Guid, string>(apps.Names);
            var page = await api.ListClientsAsync(session, AppFilter, cursor, PageSize, ct);
            Items = page.Items;
            NextCursor = page.NextCursor;
            // An application the list lacks (beyond the bounded read, or newer than the cached list): look up just those.
            var missing = Items.Select(c => c.AppId).Distinct().Where(i => !_names.ContainsKey(i)).ToList();
            if (missing.Count > 0)
                foreach (var (id, name) in await Users.UserAccess.AppNamesAsync(api, session, missing, ct)) _names[id] = name;
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == HttpStatusCode.BadRequest)
        {
            return RedirectToPage(new { app = AppFilter }); // an edited or outdated cursor: back to the first page
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex) || ex.Status == HttpStatusCode.NotFound)
        {
            log.LogInformation("Listing clients was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            Error = "Could not list clients.";
        }
        return Page();
    }

    /// <summary>The link to the next page, keeping the filter.</summary>
    public string NextHref() =>
        "/Clients?" + (AppFilter is { } a ? $"app={a}&" : "") + "cursor=" + Uri.EscapeDataString(NextCursor!);
}
