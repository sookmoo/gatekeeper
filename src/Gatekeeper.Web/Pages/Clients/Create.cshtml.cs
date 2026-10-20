using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Clients;

public class CreateModel(GatekeeperApi api, ILogger<CreateModel> log) : PageModel
{
    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? App { get; set; }
    // The browser sends the hidden "false" and, when ticked, "true" as well: read all values (see FormFlag).
    [BindProperty(Name = "IsActive")] public string[]? IsActiveValues { get; set; }
    [BindProperty] public string? Nonce { get; set; }

    /// <summary>The form's state: a missing field (a hand-made POST) is the API default, active.</summary>
    public bool? IsActive { get; private set; }
    /// <summary>The one-time value of the form being shown.</summary>
    public string FormNonce { get; private set; } = "";

    public List<AppDto> Apps { get; private set; } = [];
    public string? Error { get; private set; }
    /// <summary>Set only on the answer to a successful POST: the one place the secret is rendered.</summary>
    public SecretView? Created { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        IsActive = true;
        FormNonce = HttpContext.Current().IssueNonce(ClientAccess.CreatePurpose);
        Apps = (await ClientAccess.AppsAsync(api, HttpContext.Current(), ct)).Choices;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var session = HttpContext.Current();
        IsActive = FormFlag.Parse(IsActiveValues);
        if (FormFlag.HasInvalid(IsActiveValues)) return await FailAsync(HttpStatusCode.BadRequest, ClientAccess.GenericBadRequestText, ct);
        // One submit per form: a reload, a back button or a double click must not create a second client.
        if (!session.ConsumeNonce(ClientAccess.CreatePurpose, Nonce))
        {
            return await FailAsync(HttpStatusCode.Conflict, ClientAccess.AlreadyDoneText, ct);
        }
        if (!Guid.TryParse(App, out var appId)) return await FailAsync(HttpStatusCode.BadRequest, "Choose an application.", ct);
        try
        {
            // Not the request's token: once the API may have committed, the secret must come back to this server even if the browser went away.
            var created = await api.CreateClientAsync(session, Name?.Trim() ?? "", appId, IsActive ?? true, CancellationToken.None);
            // Rendered in this very response (no redirect, no TempData, cookie or query string) and never again.
            SecretResponse.Protect(Response);
            Created = new SecretView(created.Id, created.Name, created.Secret, false);
            return Page();
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound(); // the application does not exist
        }
        catch (ApiException ex) when (Users.UserAccess.IsRefusal(ex))
        {
            log.LogInformation("Creating a client was refused with status {Status}: {Detail}", (int)ex.Status, Users.UserAccess.ForLog(ex.Message));
            return await FailAsync(ex.Status, ClientAccess.SaveRefusalText(ex), ct);
        }
        catch (Exception ex) when (ClientAccess.IsUncertain(ex))
        {
            log.LogWarning("Creating a client got no clear answer ({Kind}); it may have been created", ex is ApiException api ? ((int)api.Status).ToString() : ex.GetType().Name);
            return await FailAsync(ex is ApiException api2 ? api2.Status : HttpStatusCode.BadGateway, ClientAccess.UncertainText, ct);
        }
    }

    private async Task<IActionResult> FailAsync(HttpStatusCode status, string error, CancellationToken ct)
    {
        Error = error;
        Response.StatusCode = (int)status;
        FormNonce = HttpContext.Current().IssueNonce(ClientAccess.CreatePurpose);
        Apps = (await ClientAccess.AppsAsync(api, HttpContext.Current(), ct)).Choices;
        return Page();
    }
}
