using System.Net;

namespace Gatekeeper.Web.Pages.Users.Sessions;

/// <summary>Helpers shared by the session pages.</summary>
public static class SessionAccess
{
    public const int MaxPages = 50;
    public const string RefusalText = "The sessions could not be changed.";

    /// <summary>What ending a session does not do. The lifetime is shown when known (the operator sets it), otherwise the wording stays generic.</summary>
    public static string LifetimeNote(TimeSpan? lifetime, bool includeRefreshNote = true)
    {
        var length = lifetime is { } l ? $"their lifetime here is {Duration(l)}" : "their lifetime is set by the operator, 15 minutes by default";
        return "Access tokens already issued stay valid until they expire (" + length + ") unless the receiving application checks with Gatekeeper. Gatekeeper's own administration access ends immediately."
            + (includeRefreshNote ? " Refresh tokens are never shown here." : "");
    }

    private static string Duration(TimeSpan t) =>
        t.TotalMinutes >= 1 && t.TotalSeconds % 60 == 0 ? $"{(int)t.TotalMinutes} minute{(t.TotalMinutes == 1 ? "" : "s")}"
        : $"{(long)t.TotalSeconds} seconds";

    /// <summary>revoked, expired or active, computed from the API's fields and the current time.</summary>
    public static string State(SessionDto s, DateTimeOffset now) =>
        s.RevokedAt is not null ? "revoked" : s.ExpiresAt <= now ? "expired" : "active";

    public static string Time(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) + " UTC";

    /// <summary>All of a user's sessions the API lists, bounded; null when the bound is hit (fail closed).</summary>
    public static async Task<List<SessionDto>?> AllAsync(GatekeeperApi api, WebSession session, Guid userId, CancellationToken ct)
    {
        var all = new List<SessionDto>();
        string? cursor = null;
        for (var pages = 0; pages < MaxPages; pages++)
        {
            var page = await api.ListUserSessionsAsync(session, userId, cursor, 200, ct);
            all.AddRange(page.Items);
            cursor = page.NextCursor;
            if (cursor is null) return all;
        }
        return null;
    }

    /// <summary>The session only if it is listed under this user (a session id that is not theirs is never acted on).</summary>
    public static async Task<SessionDto?> FindAsync(GatekeeperApi api, WebSession session, Guid userId, Guid sessionId, CancellationToken ct)
    {
        string? cursor = null;
        for (var pages = 0; pages < MaxPages; pages++)
        {
            var page = await api.ListUserSessionsAsync(session, userId, cursor, 200, ct);
            if (page.Items.FirstOrDefault(s => s.Id == sessionId) is { } found) return found;
            cursor = page.NextCursor;
            if (cursor is null) return null;
        }
        return null;
    }

    public static bool IsNotFound(ApiException ex) => ex.Status == HttpStatusCode.NotFound;
}
