using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Gatekeeper.Web;

public sealed record AppDto(Guid Id, string Name, long Version = 0);

public sealed record RoleDto(Guid Id, Guid AppId, string Name, string Description, long Version = 0);

public sealed record UserDto(Guid Id, string Username, string Email, string DisplayName, bool IsActive, string Kind, DateTimeOffset? ExpiresAt, long Version = 0);

public sealed record SessionDto(Guid Id, Guid UserId, Guid AppId, DateTimeOffset CreatedAt, DateTimeOffset LastUsedAt, DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt);

public sealed record RevokedDto(int Revoked);

public sealed record MeDto(Guid Id, string Username, string DisplayName, string Email, string Kind, DateTimeOffset? ExpiresAt);

/// <summary>One of the signed-in user's own sessions; <see cref="Current"/> marks the one this UI session runs on.</summary>
public sealed record OwnSessionDto(Guid Id, Guid AppId, string? AppName, DateTimeOffset CreatedAt, DateTimeOffset LastUsedAt, DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt, bool Current)
{
    public SessionDto AsSession(Guid userId) => new(Id, userId, AppId, CreatedAt, LastUsedAt, ExpiresAt, RevokedAt);
}

public sealed record ClientDto(Guid Id, string Name, Guid AppId, bool IsActive, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, long Version = 0);

/// <summary>A new client with its one-time secret. ToString never prints the secret, so logging the object cannot leak it.</summary>
public sealed record ClientCreatedDto(Guid Id, string Name, Guid AppId, bool IsActive, string Secret)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Id = ").Append(Id).Append(", Name = ").Append(Name);
        return true;
    }
}

/// <summary>A rotated secret. ToString never prints it.</summary>
public sealed record SecretDto(string Secret)
{
    private bool PrintMembers(System.Text.StringBuilder builder) => false;
}

/// <summary>Own password change body. ToString prints nothing, so logging the object cannot leak either password.</summary>
public sealed record OwnPasswordBody(
    [property: System.Text.Json.Serialization.JsonPropertyName("currentPassword")] string CurrentPassword,
    [property: System.Text.Json.Serialization.JsonPropertyName("newPassword")] string NewPassword)
{
    private bool PrintMembers(System.Text.StringBuilder builder) => false;
}

public sealed record AuditDto(Guid Id, DateTimeOffset At, string Actor, string Action, string? Target, string Outcome, string? Detail, string? Address);

public sealed record Page<T>(List<T> Items, string? NextCursor);

/// <summary>An error answered by the Gatekeeper API (or its absence): the status and a readable message.</summary>
public sealed class ApiException(HttpStatusCode status, string message, string? code = null) : Exception(message)
{
    public HttpStatusCode Status { get; } = status;

    /// <summary>The API's machine-readable problem code, when it sent a known one (for example a wrong current password, a 403 that is not "not allowed").</summary>
    public string? Code { get; } = code;

    public const string WrongCurrentPassword = "current-password-incorrect";
}

/// <summary>The API no longer accepts this session (ended, revoked or its refresh token expired): sign in again.</summary>
public sealed class SessionEndedException : Exception;

/// <summary>
/// Calls the Gatekeeper API as the signed-in administrator: every request carries that administrator's own access token,
/// so the audit trail names the real person. The access token is renewed with the refresh token when it is about to expire.
/// </summary>
public sealed class GatekeeperApi(HttpClient http, WebSessions sessions, TimeProvider time, IHttpContextAccessor? context = null)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly TimeSpan RenewBefore = TimeSpan.FromSeconds(30);

    /// <summary>The reserved application whose "admin" role grants access to this UI.</summary>
    public const string AdminApplication = "gatekeeper";

    /// <param name="replacing">The web session the browser came with: dropped (and its API session ended) only if the new session is admitted; a refused sign-in leaves it alone.</param>
    public async Task<WebSession> LoginAsync(string username, string password, CancellationToken ct, WebSession? replacing = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "v1/auth/login")
        {
            Content = JsonContent.Create(new { username, password, application = AdminApplication, refresh = true }),
        };
        ForwardClientAddress(request);
        var tokens = await ReadTokensAsync(await SendRawAsync(request, ct), ct);
        var ended = new List<WebSession>();
        try
        {
            var created = sessions.Create(username, tokens, ended, replacing);
            foreach (var old in ended) await LogoutAsync(old, CancellationToken.None); // best effort: their API sessions end too
            return created;
        }
        catch (WebSessionLimitException)
        {
            // The API session just started would be orphaned: end it, then refuse.
            ended.Add(new WebSession("-", username, tokens, time.GetUtcNow()));
            foreach (var old in ended) await LogoutAsync(old, CancellationToken.None);
            throw;
        }
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
        catch (Exception ex) when (ex is ApiException or HttpRequestException or TaskCanceledException or OperationCanceledException)
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

    public Task<AppDto> RenameAppAsync(WebSession s, Guid id, string name, long version, CancellationToken ct) =>
        SendAsync<AppDto>(s, HttpMethod.Patch, $"v1/applications/{id}", new { name }, ct, version);

    public async Task DeleteAppAsync(WebSession s, Guid id, long version, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/applications/{id}", null, ct, version);

    public static bool IsReserved(AppDto app) => string.Equals(app.Name, AdminApplication, StringComparison.OrdinalIgnoreCase);

    public Task<Page<RoleDto>> ListRolesAsync(WebSession s, Guid appId, string? cursor, int limit, CancellationToken ct) =>
        SendAsync<Page<RoleDto>>(s, HttpMethod.Get, $"v1/applications/{appId}/roles?limit={limit}" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"), null, ct);

    public Task<RoleDto> GetRoleAsync(WebSession s, Guid id, CancellationToken ct) =>
        SendAsync<RoleDto>(s, HttpMethod.Get, $"v1/roles/{id}", null, ct);

    public Task<RoleDto> CreateRoleAsync(WebSession s, Guid appId, string name, string description, CancellationToken ct) =>
        SendAsync<RoleDto>(s, HttpMethod.Post, $"v1/applications/{appId}/roles", new { name, description }, ct);

    public Task<RoleDto> UpdateRoleAsync(WebSession s, Guid id, string name, string description, long version, CancellationToken ct) =>
        SendAsync<RoleDto>(s, HttpMethod.Patch, $"v1/roles/{id}", new { name, description }, ct, version);

    public async Task DeleteRoleAsync(WebSession s, Guid id, long version, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/roles/{id}", null, ct, version);

    public Task<Page<UserDto>> ListUsersAsync(WebSession s, string? kind, bool? active, string? username, string? cursor, int limit, CancellationToken ct)
    {
        var path = $"v1/users?limit={limit}";
        if (kind is not null) path += $"&kind={Uri.EscapeDataString(kind)}";
        if (active is { } a) path += $"&active={(a ? "true" : "false")}";
        if (!string.IsNullOrEmpty(username)) path += $"&username={Uri.EscapeDataString(username)}";
        if (cursor is not null) path += $"&cursor={Uri.EscapeDataString(cursor)}";
        return SendAsync<Page<UserDto>>(s, HttpMethod.Get, path, null, ct);
    }

    public Task<UserDto> GetUserAsync(WebSession s, Guid id, CancellationToken ct) =>
        SendAsync<UserDto>(s, HttpMethod.Get, $"v1/users/{id}", null, ct);

    public Task<UserDto> CreateUserAsync(WebSession s, string username, string email, string displayName, string kind, DateTimeOffset? expiresAt, CancellationToken ct) =>
        SendAsync<UserDto>(s, HttpMethod.Post, "v1/users", new { username, email, displayName, kind, expiresAt }, ct);

    /// <summary>A null <paramref name="expiresAt"/> leaves the expiry unchanged (a test user) or gives the default (a person made a test user).</summary>
    public Task<UserDto> UpdateUserAsync(WebSession s, Guid id, string? username, string? email, string? displayName, bool? isActive, string? kind, DateTimeOffset? expiresAt, long version, CancellationToken ct) =>
        SendAsync<UserDto>(s, HttpMethod.Patch, $"v1/users/{id}", new { username, email, displayName, isActive, kind, expiresAt }, ct, version);

    public async Task DeleteUserAsync(WebSession s, Guid id, long version, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/users/{id}", null, ct, version);

    /// <summary>The roles a user holds (optionally only those of one application).</summary>
    public Task<Page<RoleDto>> ListUserRolesAsync(WebSession s, Guid userId, Guid? appId, string? cursor, int limit, CancellationToken ct) =>
        SendAsync<Page<RoleDto>>(s, HttpMethod.Get, $"v1/users/{userId}/roles?limit={limit}" + (appId is { } a ? $"&application={a}" : "") + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"), null, ct);

    public async Task AssignUserRoleAsync(WebSession s, Guid userId, Guid roleId, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Put, $"v1/users/{userId}/roles/{roleId}", null, ct);

    public async Task RevokeUserRoleAsync(WebSession s, Guid userId, Guid roleId, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/users/{userId}/roles/{roleId}", null, ct);

    /// <summary>Sets a user's password. The password only travels in the request body: it is never part of a URL, log line or exception text.</summary>
    public async Task SetPasswordAsync(WebSession s, Guid userId, string password, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Put, $"v1/users/{userId}/password", new { password }, ct);

    /// <summary>A user's sessions as the API lists them (refresh tokens are never part of them).</summary>
    public Task<Page<SessionDto>> ListUserSessionsAsync(WebSession s, Guid userId, string? cursor, int limit, CancellationToken ct) =>
        SendAsync<Page<SessionDto>>(s, HttpMethod.Get, $"v1/users/{userId}/sessions?limit={limit}" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"), null, ct);

    /// <summary>One session of the user; 404 when it does not exist or is another user's.</summary>
    public Task<SessionDto> GetUserSessionAsync(WebSession s, Guid userId, Guid sessionId, CancellationToken ct) =>
        SendAsync<SessionDto>(s, HttpMethod.Get, $"v1/users/{userId}/sessions/{sessionId}", null, ct);

    public async Task RevokeSessionAsync(WebSession s, Guid userId, Guid sessionId, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/users/{userId}/sessions/{sessionId}", null, ct);

    /// <summary>Revokes all sessions of a user and returns how many the API ended.</summary>
    public async Task<int> RevokeUserSessionsAsync(WebSession s, Guid userId, CancellationToken ct) =>
        (await SendAsync<RevokedDto>(s, HttpMethod.Delete, $"v1/users/{userId}/sessions", null, ct)).Revoked;

    /// <summary>
    /// Changes the signed-in user's own password. Both passwords only travel in the request body. The browser's address goes along as
    /// <c>X-Forwarded-For</c> so the API's per-address throttle sees the real client. A wrong current password is a 403 with
    /// <see cref="ApiException.WrongCurrentPassword"/> (the session stays valid); 429 means throttled.
    /// </summary>
    public async Task ChangeOwnPasswordAsync(WebSession s, string currentPassword, string newPassword, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Put, "v1/me/password", new OwnPasswordBody(currentPassword, newPassword), ct, forwardAddress: true);

    /// <summary>The signed-in user's own account (any user, not only administrators).</summary>
    public Task<MeDto> GetMeAsync(WebSession s, CancellationToken ct) =>
        SendAsync<MeDto>(s, HttpMethod.Get, "v1/me", null, ct);

    /// <summary>The signed-in user's own active sessions (at most 20 can exist, so one page of 200 holds them all).</summary>
    public async Task<List<OwnSessionDto>> ListOwnSessionsAsync(WebSession s, CancellationToken ct) =>
        (await SendAsync<Page<OwnSessionDto>>(s, HttpMethod.Get, "v1/me/sessions?limit=200", null, ct)).Items;

    public async Task RevokeOwnSessionAsync(WebSession s, Guid sessionId, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/me/sessions/{sessionId}", null, ct);

    /// <summary>Ends all other sessions of the signed-in user and returns how many.</summary>
    public async Task<int> RevokeOtherOwnSessionsAsync(WebSession s, CancellationToken ct) =>
        (await SendAsync<RevokedDto>(s, HttpMethod.Delete, "v1/me/sessions", null, ct)).Revoked;

    public Task<Page<ClientDto>> ListClientsAsync(WebSession s, Guid? appId, string? cursor, int limit, CancellationToken ct) =>
        SendAsync<Page<ClientDto>>(s, HttpMethod.Get, $"v1/clients?limit={limit}" + (appId is { } a ? $"&application={a}" : "") + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"), null, ct);

    public Task<ClientDto> GetClientAsync(WebSession s, Guid id, CancellationToken ct) =>
        SendAsync<ClientDto>(s, HttpMethod.Get, $"v1/clients/{id}", null, ct);

    /// <summary>Creates a client; the answer carries its one-time secret, which the caller must not store or log.</summary>
    public Task<ClientCreatedDto> CreateClientAsync(WebSession s, string name, Guid appId, bool isActive, CancellationToken ct) =>
        SendAsync<ClientCreatedDto>(s, HttpMethod.Post, "v1/clients", new { name, application = appId, isActive }, ct);

    /// <summary>A null field is left unchanged. <paramref name="version"/> is sent as <c>If-Match</c>: a changed client answers 412.</summary>
    public Task<ClientDto> UpdateClientAsync(WebSession s, Guid id, string? name, bool? isActive, long version, CancellationToken ct) =>
        SendAsync<ClientDto>(s, HttpMethod.Patch, $"v1/clients/{id}", new { name, isActive }, ct, version);

    public async Task DeleteClientAsync(WebSession s, Guid id, long version, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/clients/{id}", null, ct, version);

    /// <summary>Replaces a client's secret and returns the new one (shown once; never store or log it).</summary>
    public async Task<string> RotateClientSecretAsync(WebSession s, Guid id, CancellationToken ct) =>
        (await SendAsync<SecretDto>(s, HttpMethod.Post, $"v1/clients/{id}/secret", null, ct)).Secret;

    /// <summary>The roles a client holds (all of its own application).</summary>
    public Task<Page<RoleDto>> ListClientRolesAsync(WebSession s, Guid clientId, string? cursor, int limit, CancellationToken ct) =>
        SendAsync<Page<RoleDto>>(s, HttpMethod.Get, $"v1/clients/{clientId}/roles?limit={limit}" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"), null, ct);

    public async Task AssignClientRoleAsync(WebSession s, Guid clientId, Guid roleId, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Put, $"v1/clients/{clientId}/roles/{roleId}", null, ct);

    public async Task RevokeClientRoleAsync(WebSession s, Guid clientId, Guid roleId, CancellationToken ct) =>
        await SendAsync<object>(s, HttpMethod.Delete, $"v1/clients/{clientId}/roles/{roleId}", null, ct);

    /// <summary>Audit events, newest first; actor and action are exact-match filters (null or empty: no filter).</summary>
    public Task<Page<AuditDto>> ListAuditAsync(WebSession s, string? actor, string? action, string? cursor, int limit, CancellationToken ct)
    {
        var path = $"v1/audit?limit={limit}";
        if (!string.IsNullOrEmpty(actor)) path += $"&actor={Uri.EscapeDataString(actor)}";
        if (!string.IsNullOrEmpty(action)) path += $"&action={Uri.EscapeDataString(action)}";
        if (cursor is not null) path += $"&cursor={Uri.EscapeDataString(cursor)}";
        return SendAsync<Page<AuditDto>>(s, HttpMethod.Get, path, null, ct);
    }

    /// <summary>The "admin" role of the reserved application: the one that grants access to this UI.</summary>
    public static bool IsAdminRole(AppDto app, RoleDto role) =>
        IsReserved(app) && string.Equals(role.Name, "admin", StringComparison.OrdinalIgnoreCase);

    private async Task<T> SendAsync<T>(WebSession s, HttpMethod method, string path, object? body, CancellationToken ct, long? ifMatchVersion = null, bool forwardAddress = false)
    {
        await EnsureFreshAsync(s, ct);
        using var request = new HttpRequestMessage(method, path);
        if (forwardAddress) ForwardClientAddress(request);
        // A write that carries a version is conditional: the API answers 412 when the resource changed since it was read.
        if (ifMatchVersion is { } v) request.Headers.TryAddWithoutValidation("If-Match", $"\"{v.ToString(System.Globalization.CultureInfo.InvariantCulture)}\"");
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

    /// <summary>
    /// Login and refresh are throttled by the API per client address. The API only sees this server, so the browser's address goes along as
    /// <c>X-Forwarded-For</c> (replacing whatever the browser sent: this server has already resolved the real client). The API honours it only
    /// from the proxies it is configured to trust (<c>Auth__TrustedProxies</c>); otherwise it is ignored.
    /// </summary>
    private void ForwardClientAddress(HttpRequestMessage request)
    {
        if (context?.HttpContext?.Connection.RemoteIpAddress is { } address)
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString());
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
            ForwardClientAddress(request);
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
            var code = response.StatusCode == HttpStatusCode.Forbidden && ProblemCode(text) == ApiException.WrongCurrentPassword ? ApiException.WrongCurrentPassword : null;
            throw new ApiException(response.StatusCode, response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => "Not signed in.",
                HttpStatusCode.Forbidden => "You are not allowed to do that.",
                HttpStatusCode.TooManyRequests => "Too many attempts. Try again later.",
                HttpStatusCode.ServiceUnavailable => "The Gatekeeper API is unavailable.",
                _ when (int)response.StatusCode >= 500 => "The Gatekeeper API reported an error.",
                _ when (int)response.StatusCode is >= 300 and < 400 => "The API answered with a redirect, which is not followed.",
                _ => Describe(text) ?? response.ReasonPhrase ?? response.StatusCode.ToString(),
            }, code);
        }
    }

    private static string? ProblemCode(string text)
    {
        try
        {
            var root = JsonDocument.Parse(text).RootElement;
            return root.ValueKind == JsonValueKind.Object && root.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
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
