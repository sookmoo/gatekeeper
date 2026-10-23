using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Audit;

public class IndexModel(GatekeeperApi api, ILogger<IndexModel> log) : PageModel
{
    private const int PageSize = 50;
    private const int MaxFilter = 202; // the API stores at most 200 runes (up to 201 UTF-16 units) per field, so a longer filter matches nothing
    private const int MaxShown = 200;

    public List<AuditDto> Items { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Error { get; private set; }
    public string Actor { get; private set; } = "";
    public string Action { get; private set; } = "";

    // The list has no form that posts: a crafted POST is a plain 404.
    public IActionResult OnPost() => NotFound();

    /// <summary>Display text capped in length (the API already caps and sanitises; the view encodes it).</summary>
    public static string Cap(string? text) => text is null ? "" : text.Length <= MaxShown ? text : text[..(char.IsHighSurrogate(text[MaxShown - 1]) ? MaxShown - 1 : MaxShown)] + "...";

    public static string Time(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

    public async Task<IActionResult> OnGetAsync(string? actor, string? action, string? cursor, CancellationToken ct)
    {
        Actor = actor ?? "";
        Action = action ?? "";
        // A cursor the API would refuse anyway (empty, too long, wrong characters) goes back to the first page without a call.
        if (cursor is not null && (cursor.Length is 0 or > 64 || !cursor.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-')))
            return RedirectToPage(new { actor = Actor.Length > 0 ? Actor : null, action = Action.Length > 0 ? Action : null });
        if (Actor.Length > MaxFilter || Action.Length > MaxFilter) return Page(); // matches nothing: no call
        try
        {
            var page = await api.ListAuditAsync(HttpContext.Current(), Actor, Action, cursor, PageSize, ct);
            Items = page.Items;
            NextCursor = page.NextCursor;
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == HttpStatusCode.BadRequest)
        {
            return RedirectToPage(new { actor = Actor.Length > 0 ? Actor : null, action = Action.Length > 0 ? Action : null }); // an edited or outdated cursor: back to the first page
        }
        catch (ApiException ex) when (ex.Status is HttpStatusCode.BadRequest or HttpStatusCode.NotFound)
        {
            log.LogInformation("Listing audit events was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            Error = "Could not list audit events.";
        }
        return Page();
    }

    /// <summary>The link to the next page, keeping the filters (everything escaped).</summary>
    public string NextHref() =>
        "/Audit?" + (Actor.Length > 0 ? "actor=" + Uri.EscapeDataString(Actor) + "&" : "") + (Action.Length > 0 ? "action=" + Uri.EscapeDataString(Action) + "&" : "")
        + "cursor=" + Uri.EscapeDataString(NextCursor!);
}
