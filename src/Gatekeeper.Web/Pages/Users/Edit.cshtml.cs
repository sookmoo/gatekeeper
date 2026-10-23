using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Users;

public class EditModel(GatekeeperApi api, WebSessions sessions, ILogger<EditModel> log) : PageModel
{
    [BindProperty] public string? Username { get; set; }
    [BindProperty] public string? Email { get; set; }
    [BindProperty] public string? DisplayName { get; set; }
    [BindProperty] public string? Kind { get; set; }
    [BindProperty] public string? Expiry { get; set; }
    // The browser sends the hidden "false" and, when ticked, "true" as well: read all values (see FormFlag).
    [BindProperty(Name = "IsActive")] public string[]? IsActiveValues { get; set; }
    /// <summary>The form's state. Not sent (a hand-made POST) means unchanged, never "off".</summary>
    public bool? IsActive { get; private set; }
    // The values the form was loaded with. Only fields that differ from them are sent, so a stale form cannot undo
    // a change another administrator made meanwhile. Missing (not from our form): the values loaded now.
    [BindProperty] public string? OrigUsername { get; set; }
    [BindProperty] public string? OrigEmail { get; set; }
    [BindProperty] public string? OrigDisplayName { get; set; }
    [BindProperty] public string? OrigKind { get; set; }
    [BindProperty] public string? OrigExpiry { get; set; }
    [BindProperty] public string? OrigIsActive { get; set; }
    /// <summary>The version the hidden field carries: the one the form was opened with, or the fresh one after a refusal that re-reads the user.</summary>
    public long HiddenVersion { get; private set; }
    /// <summary>The user as the API holds it (the heading shows its current name, not what was typed).</summary>
    public UserDto Current { get; private set; } = null!;
    public string? Error { get; private set; }
    /// <summary>The user is the signed-in administrator's own account.</summary>
    public bool IsSelf => HttpContext.Current().UserId is { } me && me == Current.Id;

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        Username = Current.Username;
        Email = Current.Email;
        DisplayName = Current.DisplayName;
        Kind = Current.Kind;
        Expiry = UserForm.FormatExpiry(Current.ExpiresAt);
        IsActive = Current.IsActive;
        HiddenVersion = Current.Version;
        OrigUsername = Username;
        OrigEmail = Email;
        OrigDisplayName = DisplayName;
        OrigKind = Kind;
        OrigExpiry = Expiry;
        OrigIsActive = IsActive == true ? "true" : "false";
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        IsActive = FormFlag.Parse(IsActiveValues);
        // Never an unconditional write: without a usable version nothing is sent and the form is shown again with the current values.
        if (!FormVersion.TryRead(Request, out var version)) return ShowCurrent(FormVersion.MissingText, HttpStatusCode.BadRequest);
        HiddenVersion = version;
        if (!UserForm.IsKind(Kind)) return Fail(UserForm.KindText);
        if (!UserForm.TryParseExpiry(Expiry, out var expiresAt)) return Fail(UserForm.ExpiryText);
        var username = Username?.Trim() ?? "";
        var email = Email?.Trim() ?? "";
        var displayName = DisplayName?.Trim() ?? "";
        var origActive = OrigIsActive is null ? Current.IsActive : OrigIsActive == "true";
        var origExpiryText = OrigExpiry ?? UserForm.FormatExpiry(Current.ExpiresAt);
        var origKind = OrigKind ?? Current.Kind;
        var origExpiryKnown = UserForm.TryParseExpiry(origExpiryText, out var origExpiry);

        // Only a test user has an expiry. Empty or unchanged (as shown, to the second) sends nothing, so the API keeps the
        // stored value or, for a person made a test user, gives the default.
        DateTimeOffset? sendExpiry = Kind == "test" && expiresAt is { } e && !(origExpiryKnown && origExpiry is not null && UserForm.SameToTheSecond(e, origExpiry)) ? e : null;
        string? sendUsername = username != (OrigUsername ?? Current.Username) ? username : null;
        string? sendEmail = email != (OrigEmail ?? Current.Email) ? email : null;
        string? sendDisplay = displayName != (OrigDisplayName ?? Current.DisplayName) ? displayName : null;
        string? sendKind = Kind != origKind ? Kind : null;
        // A missing value (a hand-made POST) means unchanged, never "off".
        bool? sendActive = IsActive is { } active && active != origActive ? active : null;
        if (sendUsername is null && sendEmail is null && sendDisplay is null && sendKind is null && sendActive is null && sendExpiry is null)
            return RedirectToPage("Index", new { done = "updated" });
        try
        {
            var self = IsSelf;
            await api.UpdateUserAsync(HttpContext.Current(), id, sendUsername, sendEmail, sendDisplay, sendActive, sendKind, sendExpiry, version, ct);
            if (self && sendActive == false)
            {
                // Deactivated their own account: end the web session now rather than when the API's admin check notices.
                var session = HttpContext.Current();
                await api.LogoutAsync(session, ct); // revokes the refresh session too (best effort)
                sessions.Remove(session.Id);
                SessionCookie.Clear(HttpContext);
                return Redirect("/Login?ended=1");
            }
            return RedirectToPage("Index", new { done = "updated" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Updating a user was refused as stale: {Detail}", UserAccess.ForLog(ex.Message));
            return await ShowFreshAsync(id, FormVersion.ChangedText, HttpStatusCode.PreconditionFailed, ct);
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            return Fail(ex.Message, ex.Status);
        }
    }

    // Shows the user as the API holds it now, with its version, instead of what was typed.
    private async Task<IActionResult> ShowFreshAsync(Guid id, string error, HttpStatusCode status, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        return ShowCurrent(error, status);
    }

    private IActionResult ShowCurrent(string error, HttpStatusCode status)
    {
        Username = Current.Username;
        Email = Current.Email;
        DisplayName = Current.DisplayName;
        Kind = Current.Kind;
        Expiry = UserForm.FormatExpiry(Current.ExpiresAt);
        IsActive = Current.IsActive;
        HiddenVersion = Current.Version;
        OrigUsername = Username;
        OrigEmail = Email;
        OrigDisplayName = DisplayName;
        OrigKind = Kind;
        OrigExpiry = Expiry;
        OrigIsActive = Current.IsActive ? "true" : "false";
        return Fail(error, status);
    }

    private IActionResult Fail(string error, HttpStatusCode? apiStatus = null)
    {
        Error = error;
        if (apiStatus is { } status) Response.StatusCode = (int)status;
        return Page();
    }

    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            Current = await api.GetUserAsync(HttpContext.Current(), id, ct);
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
