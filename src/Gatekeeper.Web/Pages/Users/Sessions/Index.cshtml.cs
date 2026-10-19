using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users.Sessions;

public record SessionRow(SessionDto Session, string? AppName, string State, bool IsOwn);

public class IndexModel(GatekeeperApi api, TimeProvider time) : PageModel
{
    private const int PageSize = 25;

    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["revoked"] = "Session revoked.",
    };

    public UserDto Target { get; private set; } = null!;
    public List<SessionRow> Items { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Done { get; private set; }
    public TimeSpan? Lifetime => HttpContext.Current().AccessLifetime;

    // The list has no form: a crafted POST is a plain 404, not a page without data.
    public IActionResult OnPost() => NotFound();

    // The count comes from the query string, so the page parses it itself: only a plain number in a sane range is shown.
    private static string? RevokedAllText(string? n)
    {
        if (!int.TryParse(n, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var count) || count > 100_000) return null;
        return count == 0 ? "No sessions were active." : count == 1 ? "1 session revoked." : $"{count} sessions revoked.";
    }

    public async Task<IActionResult> OnGetAsync(Guid id, string? cursor, string? done, string? n, CancellationToken ct)
    {
        Done = done switch
        {
            "revokedall" => RevokedAllText(n),
            not null when Messages.TryGetValue(done, out var message) => message,
            _ => null,
        };
        try
        {
            var me = HttpContext.Current();
            Target = await api.GetUserAsync(me, id, ct);
            var page = await api.ListUserSessionsAsync(me, id, cursor, PageSize, ct);
            NextCursor = page.NextCursor;
            var names = await UserAccess.AppNamesAsync(api, me, page.Items.Select(s => s.AppId).ToList(), ct);
            var now = time.GetUtcNow();
            var own = me.UserId == id ? me.ApiSessionId : null;
            Items = page.Items.Select(s =>
            {
                names.TryGetValue(s.AppId, out var app);
                return new SessionRow(s, app, SessionAccess.State(s, now), own is { } o && o == s.Id);
            }).ToList();
        }
        catch (ApiException ex) when (SessionAccess.IsNotFound(ex))
        {
            return NotFound();
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == System.Net.HttpStatusCode.BadRequest)
        {
            return RedirectToPage(new { id }); // an edited or outdated cursor: back to the first page
        }
        return Page();
    }
}
