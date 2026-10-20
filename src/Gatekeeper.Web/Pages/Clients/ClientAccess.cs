using System.Net;

namespace Gatekeeper.Web.Pages.Clients;

/// <summary>Helpers shared by the client pages.</summary>
public static class ClientAccess
{
    private const int AppPageSize = 200;
    private const int MaxAppPages = 5;

    public const string NameRulesText = "The client name is not valid: lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 64 characters, and not like a GUID.";

    /// <summary>The applications a client can belong to, with all names (the reserved one is in <paramref name="all"/> but not in <paramref name="choices"/>). Bounded: at most 1000 applications are read.</summary>
    public static async Task<(List<AppDto> Choices, Dictionary<Guid, string> Names)> AppsAsync(GatekeeperApi api, WebSession session, CancellationToken ct)
    {
        var choices = new List<AppDto>();
        var names = new Dictionary<Guid, string>();
        string? cursor = null;
        for (var pages = 0; pages < MaxAppPages; pages++)
        {
            var page = await api.ListAppsAsync(session, cursor, AppPageSize, ct);
            foreach (var a in page.Items)
            {
                names[a.Id] = a.Name;
                if (!GatekeeperApi.IsReserved(a)) choices.Add(a);
            }
            cursor = page.NextCursor;
            if (cursor is null) break;
        }
        return (choices, names);
    }

    public const string GenericBadRequestText = "The client could not be saved: check the values and try again.";

    /// <summary>Shown instead of a nonce-protected form that expired or was already used (a reload, a back button, a double click). Neutral: it does not say whether anything was done.</summary>
    public const string AlreadyDoneText = "This form has expired or was already used. The secret is not shown again. Check the client list before trying again.";

    /// <summary>Shown when a create or rotate got no clear answer: it may or may not have been carried out.</summary>
    public const string UncertainText = "The change may have taken effect; check the client list; for a rotation the old secret may no longer work, rotate again to get a usable secret.";

    public const string CreatePurpose = "client-create";
    public static string RotatePurpose(Guid id) => "client-rotate:" + id;

    private static readonly TimeSpan AppListTtl = TimeSpan.FromSeconds(5);

    /// <summary>A create or rotate whose outcome is unknown: the API failed or did not answer cleanly after it may have committed.</summary>
    public static bool IsUncertain(Exception ex) =>
        ex is not ApiException api || (int)api.Status >= 500;

    /// <summary>
    /// The applications for a page that only shows names and a filter: reused for a few seconds per web session so a list
    /// view is not five API calls. <paramref name="mustKnow"/> forces a fresh read when the cache lacks that application.
    /// </summary>
    public static async Task<AppListSnapshot> CachedAppsAsync(GatekeeperApi api, WebSession session, TimeProvider time, Guid? mustKnow, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (session.AppList is { } cached)
        {
            if (now - cached.At < AppListTtl && now >= cached.At)
            {
                if (mustKnow is not { } id || cached.Names.ContainsKey(id)) return cached;
            }
            else
            {
                session.DropAppList(cached); // expired: not kept for the life of the session
            }
        }
        var version = session.AppListVersion;
        var (choices, names) = await AppsAsync(api, session, ct);
        var snapshot = new AppListSnapshot(now, choices, names);
        session.TryStoreAppList(snapshot, version);
        return snapshot;
    }

    /// <summary>A fixed text for a refused create or rename; the API's wording is never shown.</summary>
    public static string SaveRefusalText(ApiException ex)
    {
        // The API names the offending field first ("name must be ..."); only a name problem gets the name rules.
        if (ex.Status == HttpStatusCode.BadRequest)
            return ex.Message.Split("; ").Any(part => part.StartsWith("name ", StringComparison.OrdinalIgnoreCase)) ? NameRulesText : GenericBadRequestText;
        if (ex.Status == HttpStatusCode.Conflict)
        {
            if (ex.Message.Contains("reserved", StringComparison.Ordinal)) return "The reserved application cannot have clients.";
            if (ex.Message.Contains("already exists", StringComparison.Ordinal)) return "A client with that name already exists.";
            return "The client could not be saved because of a conflict.";
        }
        return "The client could not be saved.";
    }
}

/// <summary>What the one-time secret page shows. ToString never prints the secret.</summary>
public sealed record SecretView(Guid ClientId, string ClientName, string Secret, bool Rotated)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("ClientId = ").Append(ClientId);
        return true;
    }
}

public static class SecretResponse
{
    /// <summary>The answer carries a secret that is shown once: no cache, no history reuse, no referrer.</summary>
    public static void Protect(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        // Also drops this page from the browser's back/forward cache. Only "cache": never "cookies" or "storage", which would end the session.
        response.Headers["Clear-Site-Data"] = "\"cache\"";
        response.Headers["Referrer-Policy"] = "no-referrer";
    }
}
