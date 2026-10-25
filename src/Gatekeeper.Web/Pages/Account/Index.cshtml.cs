using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Account;

public record OwnSessionRow(OwnSessionDto Session, string State);

/// <summary>The signed-in user's own account: a read-only profile and their sessions. Open to every signed-in user.</summary>
public class IndexModel(GatekeeperApi api, TimeProvider time) : PageModel
{
    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["revoked"] = "Session revoked.",
        ["password"] = "Password changed. Your other sessions were ended; this one stays signed in.",
    };

    public MeDto Me { get; private set; } = null!;
    public List<OwnSessionRow> Items { get; private set; } = [];
    public string? Done { get; private set; }
    public TimeSpan? Lifetime => HttpContext.Current().AccessLifetime;

    // The page has no form: a crafted POST is a plain 404, not a page without data.
    public IActionResult OnPost() => NotFound();

    // The count comes from the query string, so the page parses it itself: only a plain number in a sane range is shown.
    private static string? RevokedOthersText(string? n)
    {
        if (!int.TryParse(n, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var count) || count > 100_000) return null;
        return count == 0 ? "No other sessions were active." : count == 1 ? "1 other session revoked." : $"{count} other sessions revoked.";
    }

    public async Task<IActionResult> OnGetAsync(string? done, string? n, CancellationToken ct)
    {
        Done = done switch
        {
            "revokedothers" => RevokedOthersText(n),
            not null when Messages.TryGetValue(done, out var message) => message,
            _ => null,
        };
        var session = HttpContext.Current();
        Me = await api.GetMeAsync(session, ct);
        var now = time.GetUtcNow();
        Items = (await api.ListOwnSessionsAsync(session, ct)).Select(s => new OwnSessionRow(s, SessionState(s, now))).ToList();
        return Page();
    }

    internal static string SessionState(OwnSessionDto s, DateTimeOffset now) => Users.Sessions.SessionAccess.State(s.AsSession(Guid.Empty), now);
}
