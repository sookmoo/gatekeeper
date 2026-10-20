using System.Net;

namespace Gatekeeper.Web.Pages.Users;

/// <summary>Helpers shared by the user role and password pages.</summary>
public static class UserAccess
{
    public const int PasswordMin = 12;
    public const int PasswordMax = 128;
    public const string PasswordRulesText = "The password was not accepted. It must be 12 to 128 characters without control characters.";

    /// <summary>The signed-in administrator's access is gone (or their sessions are): drop the web session at once, after a best-effort API logout.</summary>
    public static async Task<string> EndOwnSessionAsync(GatekeeperApi api, WebSessions sessions, HttpContext http, CancellationToken ct)
    {
        var session = http.Current();
        // Local state first: a cancelled request or a failing API must not leave the web session alive.
        sessions.Remove(session.Id);
        SessionCookie.Clear(http);
        try
        {
            await api.LogoutAsync(session, CancellationToken.None); // revokes the refresh session too (best effort)
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or AccessViolationException or ThreadAbortException))
        {
            // best effort: the refresh token expires on its own
        }
        return "/Login?ended=1";
    }

    /// <summary>A fixed text for a refused role change; the API's wording is never shown.</summary>
    public static string RoleRefusalText(ApiException ex)
    {
        if (ex.Status == HttpStatusCode.Conflict)
        {
            var m = ex.Message;
            if (m.Contains("Only a person", StringComparison.Ordinal) || m.Contains("must be a person", StringComparison.Ordinal))
                return "Only a person can hold the admin role.";
            if (m.Contains("active administrator", StringComparison.Ordinal))
                return "This would leave Gatekeeper without an active administrator.";
            if (m.Contains("reserved", StringComparison.Ordinal))
                return "The reserved application only allows its admin role.";
            return "The role could not be changed because of a conflict.";
        }
        return "The role could not be changed.";
    }

    /// <summary>The API's detail for the log only: control characters removed and capped.</summary>
    public static string ForLog(string? text)
    {
        var clean = new string((text ?? "").Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) is not (System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator or System.Globalization.UnicodeCategory.Format)).ToArray());
        return clean.Length <= 200 ? clean : clean[..200];
    }

    /// <summary>Application names for the given ids with few calls: single lookups for a handful, otherwise one list call and lookups only for what it lacked.</summary>
    public static async Task<Dictionary<Guid, string>> AppNamesAsync(GatekeeperApi api, WebSession session, IReadOnlyCollection<Guid> ids, CancellationToken ct)
    {
        var names = new Dictionary<Guid, string>();
        var wanted = ids.Distinct().ToList();
        if (wanted.Count > 3)
        {
            foreach (var a in (await api.ListAppsAsync(session, null, 200, ct)).Items)
                if (wanted.Contains(a.Id)) names[a.Id] = a.Name;
        }
        foreach (var id in wanted.Where(i => !names.ContainsKey(i)))
        {
            try
            {
                names[id] = (await api.GetAppAsync(session, id, ct)).Name;
            }
            catch (ApiException ex) when (ex.Status == HttpStatusCode.NotFound)
            {
                // gone meanwhile: shown as unknown
            }
        }
        return names;
    }

    /// <summary>A refusal the page may show (a client error that is not about the session or throttling).</summary>
    public static bool IsRefusal(ApiException ex) =>
        (int)ex.Status is >= 400 and < 500 && ex.Status is not (HttpStatusCode.Unauthorized or HttpStatusCode.NotFound or HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests);
}
