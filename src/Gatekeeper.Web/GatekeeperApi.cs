using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Gatekeeper.Web;

public sealed record AppDto(Guid Id, string Name);

public sealed record Page<T>(List<T> Items, string? NextCursor);

/// <summary>An error answered by the Gatekeeper API (or its absence): the status and a readable message.</summary>
public sealed class ApiException(HttpStatusCode status, string message) : Exception(message)
{
    public HttpStatusCode Status { get; } = status;
}

/// <summary>The API no longer accepts this session (ended, revoked or its refresh token expired): sign in again.</summary>
public sealed class SessionEndedException : Exception;

/// <summary>
/// Calls the Gatekeeper API as the signed-in administrator: every request carries that administrator's own access token,
/// so the audit trail names the real person. The access token is renewed with the refresh token when it is about to expire.
/// </summary>
public sealed class GatekeeperApi(HttpClient http, WebSessions sessions, TimeProvider time)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly TimeSpan RenewBefore = TimeSpan.FromSeconds(30);

    /// <summary>The reserved application whose "admin" role grants access to this UI.</summary>
    public const string AdminApplication = "gatekeeper";

    public async Task<WebSession> LoginAsync(string username, string password, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "v1/auth/login")
        {
            Content = JsonContent.Create(new { username, password, application = AdminApplication, refresh = true }),
        };
        var tokens = await ReadTokensAsync(await SendRawAsync(request, ct), ct);
        return sessions.Create(username, tokens);
    }

    public async Task LogoutAsync(WebSession session, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "v1/auth/logout")
            {
                Content = JsonContent.Create(new { refreshToken = session.Tokens.Refresh }),
            };
            using var response = await SendRawAsync(request, ct);
        }
        catch (ApiException)
        {
            // best effort: the session is dropped here either way and the refresh token expires on its own
        }
    }

    public Task<Page<AppDto>> ListAppsAsync(WebSession s, string? cursor, int limit, CancellationToken ct) =>
        SendAsync<Page<AppDto>>(s, HttpMethod.Get, $"v1/applications?limit={limit}" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"), null, ct);

    public Task<AppDto> GetAppAsync(WebSession s, Guid id, CancellationToken ct) =>
        SendAsync<AppDto>(s, HttpMethod.Get, $"v1/applications/{id}", null, ct);

    public Task<AppDto> CreateAppAsync(WebSession s, string name, CancellationToken ct) =>
        SendAsync<AppDto>(s, HttpMethod.Post, "v1/applications", new { name }, ct);

    public Task<AppDto> RenameAppAsync(WebSession s, Guid id, string name, CancellationToken ct) =>
        SendAsync<AppDto>(s, HttpMethod.Patch, $"v1/applications/{id}", new { name }, ct);

    public async Task DeleteAppAsync(WebSession s, Guid id, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/applications/{id}", null, ct);

    private async Task<T> SendAsync<T>(WebSession s, HttpMethod method, string path, object? body, CancellationToken ct)
    {
        await EnsureFreshAsync(s, ct);
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", s.Tokens.Access);
        try
        {
            using var response = await SendRawAsync(request, ct);
            return response.StatusCode == HttpStatusCode.NoContent ? default! : (await response.Content.ReadFromJsonAsync<T>(Json, ct))!;
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
        {
            // The token was refused (session ended, user deactivated, admin role removed): this session is over.
            sessions.Remove(s.Id);
            throw new SessionEndedException();
        }
    }

    private async Task EnsureFreshAsync(WebSession s, CancellationToken ct)
    {
        if (s.Tokens.AccessExpiresAt - RenewBefore > time.GetUtcNow()) return;
        await s.RefreshLock.WaitAsync(ct);
        try
        {
            var current = s.Tokens;
            if (current.AccessExpiresAt - RenewBefore > time.GetUtcNow()) return; // a parallel request already renewed it
            using var request = new HttpRequestMessage(HttpMethod.Post, "v1/auth/refresh")
            {
                Content = JsonContent.Create(new { refreshToken = current.Refresh }),
            };
            try
            {
                s.Tokens = await ReadTokensAsync(await SendRawAsync(request, ct), ct);
            }
            catch (ApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
            {
                sessions.Remove(s.Id);
                throw new SessionEndedException();
            }
        }
        finally
        {
            s.RefreshLock.Release();
        }
    }

    private async Task<Tokens> ReadTokensAsync(HttpResponseMessage response, CancellationToken ct)
    {
        using (response)
        {
            var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
            var now = time.GetUtcNow();
            if (!body.TryGetProperty("accessToken", out var access) || !body.TryGetProperty("expiresIn", out var expires)
                || !body.TryGetProperty("refreshToken", out var refresh) || !body.TryGetProperty("refreshExpiresIn", out var refreshExpires)
                || access.GetString() is not { } a || refresh.GetString() is not { } r)
                throw new ApiException(HttpStatusCode.BadGateway, "Unexpected response from Gatekeeper.");
            return new Tokens(a, now.AddSeconds(expires.GetInt32()), r, now.AddSeconds(refreshExpires.GetInt32()));
        }
    }

    /// <summary>Sends the request; non-success answers become an <see cref="ApiException"/>. Redirects are never followed.</summary>
    private async Task<HttpResponseMessage> SendRawAsync(HttpRequestMessage request, CancellationToken ct)
    {
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (HttpRequestException)
        {
            throw new ApiException(HttpStatusCode.ServiceUnavailable, "Cannot reach the Gatekeeper API.");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ApiException(HttpStatusCode.GatewayTimeout, "The Gatekeeper API did not answer in time.");
        }

        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            throw new ApiException(response.StatusCode, response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => "Not signed in.",
                HttpStatusCode.Forbidden => "You are not allowed to do that.",
                HttpStatusCode.TooManyRequests => "Too many attempts. Try again later.",
                HttpStatusCode.ServiceUnavailable => "The Gatekeeper API is unavailable.",
                _ when (int)response.StatusCode >= 500 => "The Gatekeeper API reported an error.",
                _ when (int)response.StatusCode is >= 300 and < 400 => "The API answered with a redirect, which is not followed.",
                _ => Describe(text) ?? response.ReasonPhrase ?? response.StatusCode.ToString(),
            });
        }
    }

    // A readable message from an RFC 9457 problem details body.
    private static string? Describe(string text)
    {
        try
        {
            var root = JsonDocument.Parse(text).RootElement;
            if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object)
                return string.Join("; ", errors.EnumerateObject().Select(e => $"{e.Name} {(e.Value.ValueKind == JsonValueKind.Array ? string.Join(' ', e.Value.EnumerateArray().Select(v => v.ToString())) : e.Value.ToString())}"));
            if (root.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.String && detail.GetString() is { Length: > 0 } d) return d;
            if (root.TryGetProperty("title", out var title) && title.ValueKind == JsonValueKind.String) return title.GetString();
        }
        catch (JsonException)
        {
            // not JSON: no detail worth showing
        }
        return null;
    }
}
