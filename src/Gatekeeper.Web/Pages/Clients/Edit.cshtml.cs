using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients;

public class EditModel(GatekeeperApi api, ILogger<EditModel> log) : PageModel
{
    [BindProperty] public string? Name { get; set; }
    // The browser sends the hidden "false" and, when ticked, "true" as well: read all values (see FormFlag).
    [BindProperty(Name = "IsActive")] public string[]? IsActiveValues { get; set; }
    /// <summary>The form's state. Not sent (a hand-made POST) means unchanged, never "off".</summary>
    public bool? IsActive { get; private set; }
    // The values the form was loaded with. Only fields that differ from them are sent, so a stale form cannot undo
    // a change another administrator made meanwhile. Missing (not from our form): the values loaded now.
    [BindProperty] public string? OrigName { get; set; }
    [BindProperty] public string? OrigIsActive { get; set; }

    /// <summary>The version the hidden field carries: the one the form was opened with, or the fresh one after a refusal that re-reads the client.</summary>
    public long HiddenVersion { get; private set; }

    /// <summary>The client as the API holds it (the heading shows its current name, not what was typed).</summary>
    public ClientDto Current { get; private set; } = null!;
    public string AppName { get; private set; } = "(unknown)";
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        Name = Current.Name;
        IsActive = Current.IsActive;
        OrigName = Name;
        OrigIsActive = Current.IsActive ? "true" : "false";
        HiddenVersion = Current.Version;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        IsActive = FormFlag.Parse(IsActiveValues);
        // Never an unconditional write: without a usable version nothing is sent and the form is shown again with the current values.
        if (!FormVersion.TryRead(Request, out var version)) return ShowCurrent(FormVersion.MissingText, StatusCodes.Status400BadRequest);
        HiddenVersion = version;
        var name = Name?.Trim() ?? "";
        var origActive = OrigIsActive is null ? Current.IsActive : OrigIsActive == "true";
        string? sendName = name != (OrigName ?? Current.Name) ? name : null;
        bool? sendActive = IsActive is { } active && active != origActive ? active : null;
        if (sendName is null && sendActive is null) return RedirectToPage("Index", new { done = "updated" });
        try
        {
            await api.UpdateClientAsync(HttpContext.Current(), id, sendName, sendActive, version, ct);
            return RedirectToPage("Index", new { done = "updated" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (FormVersion.IsStale(ex))
        {
            log.LogInformation("Updating a client was refused as stale: {Detail}", Users.UserAccess.ForLog(ex.Message));
            if (!await LoadAsync(id, ct)) return NotFound();
            return ShowCurrent(FormVersion.ChangedText, StatusCodes.Status412PreconditionFailed);
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Updating a client was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            Error = ClientAccess.SaveRefusalText(ex);
            Response.StatusCode = (int)ex.Status;
            return Page();
        }
    }

    // Shows the client as the API holds it now, with its version, instead of what was typed.
    private IActionResult ShowCurrent(string error, int status)
    {
        Name = Current.Name;
        IsActive = Current.IsActive;
        OrigName = Name;
        OrigIsActive = Current.IsActive ? "true" : "false";
        HiddenVersion = Current.Version;
        Error = error;
        Response.StatusCode = status;
        return Page();
    }

    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Current = await api.GetClientAsync(session, id, ct);
            var names = await Users.UserAccess.AppNamesAsync(api, session, [Current.AppId], ct);
            if (names.TryGetValue(Current.AppId, out var n)) AppName = n;
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
