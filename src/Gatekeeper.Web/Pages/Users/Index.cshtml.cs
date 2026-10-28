using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users;

public class IndexModel(GatekeeperApi api, TimeProvider time, ILogger<IndexModel> log) : PageModel
{
    private const int PageSize = 25;

    // The only messages that can appear, chosen by a fixed key: nothing the request says is echoed back.
    private static readonly Dictionary<string, string> Messages = new()
    {
        ["created"] = "User created.",
        ["updated"] = "User updated.",
        ["deleted"] = "User deleted.",
    };

    public List<UserDto> Items { get; private set; } = [];
    public string? NextCursor { get; private set; }
    public string? Error { get; private set; }
    public string? Done { get; private set; }
    /// <summary>The filters in effect: kind (person, test, shared), active (true, false) and the exact username; anything else is ignored.</summary>
    public string? Kind { get; private set; }
    public string? Active { get; private set; }
    public string? Username { get; private set; }
    /// <summary>Case-insensitive prefixes of the username and the e-mail address (at least 2 characters), and the "usable" filter (true, false).</summary>
    public string? Prefix { get; private set; }
    public string? EmailPrefix { get; private set; }
    public string? Usable { get; private set; }

    public bool IsExpired(UserDto u) => u.ExpiresAt is { } e && e <= time.GetUtcNow();

    // The list has no form: a crafted POST is a plain 404, not a page without data.
    public IActionResult OnPost() => NotFound();

    public async Task<IActionResult> OnGetAsync(string? kind, string? active, string? username, string? prefix, string? emailPrefix, string? usable, string? cursor, string? done, CancellationToken ct)
    {
        Done = done is not null && Messages.TryGetValue(done, out var message) ? message : null;
        Kind = UserForm.IsKind(kind) ? kind : null;
        Active = active is "true" or "false" ? active : null;
        Username = string.IsNullOrWhiteSpace(username) ? null : username.Trim();
        Prefix = string.IsNullOrWhiteSpace(prefix) ? null : prefix.Trim();
        EmailPrefix = string.IsNullOrWhiteSpace(emailPrefix) ? null : emailPrefix.Trim();
        Usable = usable is "true" or "false" ? usable : null;
        // The API refuses a prefix shorter than 2 characters; say so here instead of a generic error.
        if (Prefix is { Length: < 2 } || EmailPrefix is { Length: < 2 })
        {
            Error = "A prefix needs at least 2 characters.";
            return Page();
        }
        try
        {
            var page = await api.ListUsersAsync(HttpContext.Current(), Kind, Active is null ? null : Active == "true", Username, cursor, PageSize, ct,
                Prefix, EmailPrefix, Usable is null ? null : Usable == "true");
            Items = page.Items;
            NextCursor = page.NextCursor;
        }
        catch (ApiException ex) when (cursor is not null && ex.Status == HttpStatusCode.BadRequest)
        {
            return RedirectToPage(new { kind = Kind, active = Active, username = Username, prefix = Prefix, emailPrefix = EmailPrefix, usable = Usable }); // an edited or outdated cursor: back to the first page
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests))
        {
            log.LogInformation("Listing users was refused with status {Status}", (int)ex.Status);
            Error = "Could not list users.";
        }
        return Page();
    }

    /// <summary>The link to the next page, keeping the filters.</summary>
    public string NextHref()
    {
        var parts = new List<string>();
        if (Kind is not null) parts.Add("kind=" + Uri.EscapeDataString(Kind));
        if (Active is not null) parts.Add("active=" + Active);
        if (Username is not null) parts.Add("username=" + Uri.EscapeDataString(Username));
        if (Prefix is not null) parts.Add("prefix=" + Uri.EscapeDataString(Prefix));
        if (EmailPrefix is not null) parts.Add("emailPrefix=" + Uri.EscapeDataString(EmailPrefix));
        if (Usable is not null) parts.Add("usable=" + Usable);
        parts.Add("cursor=" + Uri.EscapeDataString(NextCursor!));
        return "/Users?" + string.Join('&', parts);
    }
}
