using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients;

public class RotateModel(GatekeeperApi api, ILogger<RotateModel> log) : PageModel
{
    [BindProperty] public string? Nonce { get; set; }

    public ClientDto Target { get; private set; } = null!;
    public string AppName { get; private set; } = "(unknown)";
    /// <summary>The one-time value of the confirmation form being shown.</summary>
    public string FormNonce { get; private set; } = "";
    public string? Error { get; private set; }
    /// <summary>Set only on the answer to a successful POST: the one place the new secret is rendered.</summary>
    public SecretView? Rotated { get; private set; }

    // A GET never rotates: it only asks for confirmation.
    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        FormNonce = HttpContext.Current().IssueNonce(ClientAccess.RotatePurpose(id));
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await LoadAsync(id, ct)) return NotFound();
        var session = HttpContext.Current();
        // One rotation per confirmation: a reload, a back button or a double click must not issue another secret and invalidate the one shown.
        if (!session.ConsumeNonce(ClientAccess.RotatePurpose(id), Nonce)) return Refused(HttpStatusCode.Conflict, ClientAccess.AlreadyDoneText);
        try
        {
            // Not the request's token: once the API may have committed, the secret must come back to this server even if the browser went away.
            var secret = await api.RotateClientSecretAsync(session, id, CancellationToken.None);
            // Rendered in this very response (no redirect, no TempData, cookie or query string) and never again.
            SecretResponse.Protect(Response);
            Rotated = new SecretView(Target.Id, Target.Name, secret, true);
            return Page();
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Rotating a client secret was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            return Refused(ex.Status, "The secret could not be rotated.");
        }
        catch (Exception ex) when (ClientAccess.IsUncertain(ex))
        {
            log.LogWarning("Rotating a client secret got no clear answer ({Kind}); it may have been rotated", ex is ApiException api ? ((int)api.Status).ToString() : ex.GetType().Name);
            return Refused(ex is ApiException api2 ? api2.Status : HttpStatusCode.BadGateway, ClientAccess.UncertainText);
        }
    }

    /// <summary>The confirmation again, with a fresh one-time value, and why nothing (more) was done.</summary>
    private IActionResult Refused(HttpStatusCode status, string error)
    {
        Error = error;
        Response.StatusCode = (int)status;
        FormNonce = HttpContext.Current().IssueNonce(ClientAccess.RotatePurpose(Target.Id));
        return Page();
    }

    private async Task<bool> LoadAsync(Guid id, CancellationToken ct)
    {
        try
        {
            var session = HttpContext.Current();
            Target = await api.GetClientAsync(session, id, ct);
            var names = await Users.UserAccess.AppNamesAsync(api, session, [Target.AppId], ct);
            if (names.TryGetValue(Target.AppId, out var n)) AppName = n;
            return true;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return false;
        }
    }
}
