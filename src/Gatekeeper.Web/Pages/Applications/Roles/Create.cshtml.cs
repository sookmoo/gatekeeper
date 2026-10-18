using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages.Applications.Roles;

public class CreateModel(GatekeeperApi api) : PageModel
{
    public const string ReservedText = "This application is reserved: its roles are read-only.";

    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Description { get; set; }
    public AppDto App { get; private set; } = null!;
    public bool ReadOnly { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(Guid appId, CancellationToken ct) =>
        await LoadAsync(appId, ct) ?? Page();

    public async Task<IActionResult> OnPostAsync(Guid appId, CancellationToken ct)
    {
        if (await LoadAsync(appId, ct) is { } missing) return missing;
        try
        {
            await api.CreateRoleAsync(HttpContext.Current(), appId, Name?.Trim() ?? "", Description?.Trim() ?? "", ct);
            return RedirectToPage("Index", new { appId, done = "created" });
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500 && ex.Status != HttpStatusCode.Unauthorized)
        {
            Error = Refusal(ex);
            return Page();
        }
    }

    // The API's own wording, except for a refusal on a reserved application, which gets the fixed text.
    private string Refusal(ApiException ex)
    {
        if (!ReadOnly || ex.Status != HttpStatusCode.Conflict) return ex.Message;
        Response.StatusCode = StatusCodes.Status409Conflict;
        return ReservedText;
    }

    // Returns NotFound when the application does not exist, otherwise null.
    private async Task<IActionResult?> LoadAsync(Guid appId, CancellationToken ct)
    {
        try
        {
            App = await api.GetAppAsync(HttpContext.Current(), appId, ct);
            ReadOnly = GatekeeperApi.IsReserved(App);
            return null;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return NotFound();
        }
    }
}
