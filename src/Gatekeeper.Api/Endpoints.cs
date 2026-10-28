using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

public sealed record AppRequest(string? Name);

public sealed record RoleRequest(string? Name, string? Description);

public sealed record UserRequest(string? Username, string? Email, string? DisplayName, bool? IsActive, UserKind? Kind = null, DateTimeOffset? ExpiresAt = null);

public sealed record ClientRequest(string? Name, Guid? Application, bool? IsActive);

/// <summary>A new client with its one-time secret. ToString never prints the secret, so logging the object cannot leak it.</summary>
public sealed record ClientCreatedResponse(Guid Id, string Name, Guid AppId, bool IsActive, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, string Secret, long Version = 1) : IVersioned
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Id = ").Append(Id).Append(", Name = ").Append(Name);
        return true;
    }
}

public sealed record RevokedResponse(int Revoked);

/// <summary>A rotated secret. ToString never prints it.</summary>
public sealed record SecretResponse(string Secret)
{
    private bool PrintMembers(System.Text.StringBuilder builder) => false;
}

public sealed record PasswordRequest(string? Password);

/// <summary>Own password change. ToString never prints either password, so logging the object cannot leak them.</summary>
public sealed record OwnPasswordRequest(string? CurrentPassword, string? NewPassword)
{
    private bool PrintMembers(System.Text.StringBuilder builder) => false;
}

/// <summary>The caller's own account (read-only).</summary>
public sealed record MeResponse(Guid Id, string Username, string DisplayName, string Email, UserKind Kind, DateTimeOffset? ExpiresAt);

/// <summary>A session as its owner sees it; <see cref="Current"/> is true for the session the caller's token came from.</summary>
public sealed record OwnSession(Guid Id, Guid UserId, Guid AppId, string? AppName, DateTimeOffset CreatedAt, DateTimeOffset LastUsedAt, DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt, bool Current);

/// <summary>Adds the strong ETag (<c>"&lt;version&gt;"</c>) to every successful answer that carries a versioned resource (single-resource GET/PUT/PATCH and POST create).</summary>
public sealed class ETagFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var result = await next(context);
        var version = result switch
        {
            IVersioned v => v.Version,
            IValueHttpResult { Value: IVersioned v } => v.Version,
            _ => (long?)null,
        };
        if (version is { } n) context.HttpContext.Response.Headers.ETag = $"\"{n}\"";
        return result;
    }
}

public static class Endpoints
{
    public const string AdminPolicy = "admin";
    public const string SelfPolicy = "self";
    public const string ReadyPolicy = "ready";

    /// <summary>Problem extension <c>code</c> of the 403 for a wrong current password (the status alone also means "not allowed"; clients tell them apart by this).</summary>
    public const string WrongCurrentPasswordCode = "current-password-incorrect";
    public const string WrongCurrentPasswordText = "The current password is incorrect.";
    /// <summary>Wrong or refused attempts per user (all addresses) and per address within the throttle window before 429.</summary>
    public const int PasswordFailuresPerUser = 5;
    public const int PasswordFailuresPerAddress = 20;

    /// <summary>Exactly person, test or shared (any case): not numbers and not comma lists, which Enum.TryParse would accept.</summary>
    private static UserKind? ParseKind(string? kind) =>
        string.IsNullOrEmpty(kind) ? null
        : kind.Equals("person", StringComparison.OrdinalIgnoreCase) ? UserKind.Person
        : kind.Equals("test", StringComparison.OrdinalIgnoreCase) ? UserKind.Test
        : kind.Equals("shared", StringComparison.OrdinalIgnoreCase) ? UserKind.Shared
        : throw new ValidationException(new Dictionary<string, string> { ["kind"] = "must be person, test or shared." });

    /// <summary>The caller's If-Match header (several header lines count as one list), or null when there is none. Malformed is a 400.</summary>
    private static Precondition? IfMatch(HttpContext http) =>
        http.Request.Headers.TryGetValue(Microsoft.Net.Http.Headers.HeaderNames.IfMatch, out var values)
            ? Precondition.Parse(string.Join(",", values.OfType<string>())) // an empty header is present but matches no syntax: 400
            : null;

    /// <summary>What a user change leaves behind, for the audit detail (the trail otherwise shows only the route and status).</summary>
    private static async Task<User> Noted(HttpContext http, Task<User> change)
    {
        var u = await change;
        http.Items[AuditMiddleware.NoteKey] = UserNote(u);
        return u;
    }

    private static string UserNote(User u) =>
        $"kind={u.Kind.ToString().ToLowerInvariant()} expiresAt={(u.ExpiresAt is { } e ? e.UtcDateTime.ToString("O") : "none")} active={u.IsActive}";

    /// <summary>As <see cref="Noted"/>, plus what the change did to the user's sessions (only when it did something).</summary>
    private static async Task<User> Noted(HttpContext http, Task<(User User, SessionEffects Effects)> change)
    {
        var (u, fx) = await change;
        // A raised cut-off or ended sessions end tokens of the user: forget the cached access answers so that this instance acts at once.
        if (fx.CutOff is not null || fx.Revoked > 0) http.RequestServices.GetRequiredService<AdminAccessCheck>().Evict(u.Id);
        var note = UserNote(u);
        if (fx.Revoked > 0) note += $" sessionsRevoked={fx.Revoked}";
        if (fx.Capped > 0) note += $" sessionsCapped={fx.Capped}";
        if (fx.CutOff is { } cut) note += $" sessionsCutOff={cut.UtcDateTime:O}";
        http.Items[AuditMiddleware.NoteKey] = note;
        return u;
    }

    public static void MapApi(this IEndpointRouteBuilder routes)
    {
        MapMe(routes);
        var v1 = routes.MapGroup("/v1").RequireAuthorization(AdminPolicy).AddEndpointFilter<ETagFilter>();

        var apps = v1.MapGroup("/applications").WithTags("Applications");
        apps.MapGet("/", (AppService s, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(PageQuery.Parse(limit, cursor), ct));
        apps.MapPost("/", async (AppRequest r, AppService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(r.Name, ct);
            return Results.Created($"/v1/applications/{created.Id}", created);
        }).Produces<App>(StatusCodes.Status201Created);
        apps.MapGet("/{id:guid}", (Guid id, AppService s, CancellationToken ct) => s.GetAsync(id, ct));
        apps.MapPut("/{id:guid}", (HttpContext http, Guid id, AppRequest r, AppService s, CancellationToken ct) => s.UpdateAsync(id, r.Name, IfMatch(http), ct));
        apps.MapMethods("/{id:guid}", ["PATCH"], (HttpContext http, Guid id, AppRequest r, AppService s, CancellationToken ct) => s.PatchAsync(id, r.Name, IfMatch(http), ct));
        apps.MapDelete("/{id:guid}", async (HttpContext http, Guid id, AppService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, IfMatch(http), ct);
            return Results.NoContent();
        });
        apps.MapGet("/{id:guid}/roles", (Guid id, RoleService s, int? limit, string? cursor, CancellationToken ct) =>
            s.ListByAppAsync(id, PageQuery.Parse(limit, cursor), ct));
        apps.MapPost("/{id:guid}/roles", async (Guid id, RoleRequest r, RoleService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(id, r.Name, r.Description, ct);
            return Results.Created($"/v1/roles/{created.Id}", created);
        }).Produces<Role>(StatusCodes.Status201Created);

        var roles = v1.MapGroup("/roles").WithTags("Roles");
        roles.MapGet("/{id:guid}", (Guid id, RoleService s, CancellationToken ct) => s.GetAsync(id, ct));
        roles.MapPut("/{id:guid}", (HttpContext http, Guid id, RoleRequest r, RoleService s, CancellationToken ct) => s.UpdateAsync(id, r.Name, r.Description, IfMatch(http), ct));
        roles.MapMethods("/{id:guid}", ["PATCH"], (HttpContext http, Guid id, RoleRequest r, RoleService s, CancellationToken ct) => s.PatchAsync(id, r.Name, r.Description, IfMatch(http), ct));
        roles.MapDelete("/{id:guid}", async (HttpContext http, Guid id, RoleService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, IfMatch(http), ct);
            return Results.NoContent();
        });

        var users = v1.MapGroup("/users").WithTags("Users");
        users.MapGet("/", (UserService s, bool? active, string? username, string? kind, string? usernamePrefix, string? emailPrefix, bool? usable, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(active, username, ParseKind(kind), PageQuery.Parse(limit, cursor), ct, usernamePrefix, emailPrefix, usable))
            .WithDescription("Filters combine with AND. username is an exact match; usernamePrefix and emailPrefix are case-insensitive prefixes of at least 2 characters (wildcard characters match themselves; 400 when shorter, too long or with control characters). active filters the enabled flag only; usable=true lists accounts that are enabled and, for test users, not expired; usable=false lists the others.");
        users.MapPost("/", async (HttpContext http, UserRequest r, UserService s, CancellationToken ct) =>
        {
            var created = await Noted(http, s.CreateAsync(r.Username, r.Email, r.DisplayName, r.IsActive ?? true, r.Kind ?? UserKind.Person, r.ExpiresAt, ct));
            return Results.Created($"/v1/users/{created.Id}", created);
        }).Produces<User>(StatusCodes.Status201Created);
        users.MapGet("/{id:guid}", (Guid id, UserService s, CancellationToken ct) => s.GetAsync(id, ct));
        users.MapPut("/{id:guid}", (HttpContext http, Guid id, UserRequest r, UserService s, CancellationToken ct) =>
            Noted(http, s.UpdateWithEffectsAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, r.Kind, r.ExpiresAt, IfMatch(http), ct)))
            .WithDescription("Setting isActive from true to false ends all of the user's sessions at once. Setting it back to true (or extending the expiry of an expired test user so the account is usable again) does not bring them back: the same write raises the user's session cut-off, so every session and every access token without a session that was authenticated before that moment stays refused. Moving a test user's expiresAt earlier (or making a person a test user) caps active sessions to the new expiry; a later extension does not lengthen them.");
        users.MapMethods("/{id:guid}", ["PATCH"], (HttpContext http, Guid id, UserRequest r, UserService s, CancellationToken ct) =>
            Noted(http, s.PatchWithEffectsAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, r.Kind, r.ExpiresAt, IfMatch(http), ct)))
            .WithDescription("Setting isActive from true to false ends all of the user's sessions at once. Setting it back to true (or extending the expiry of an expired test user so the account is usable again) does not bring them back: the same write raises the user's session cut-off, so every session and every access token without a session that was authenticated before that moment stays refused. Moving a test user's expiresAt earlier (or making a person a test user) caps active sessions to the new expiry; a later extension does not lengthen them.");
        users.MapDelete("/{id:guid}", async (HttpContext http, Guid id, UserService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, IfMatch(http), ct);
            return Results.NoContent();
        });
        users.MapPut("/{id:guid}/password", async (HttpContext http, Guid id, PasswordRequest r, CredentialService s, AdminAccessCheck access, CancellationToken ct) =>
        {
            DateTimeOffset? cutOff;
            try { cutOff = await s.SetPasswordAsync(id, r.Password, ct); }
            finally { access.Evict(id); } // this instance acts at once (also when a step after the store write failed); others follow after their 10 s cache
            if (cutOff is { } cut) http.Items[AuditMiddleware.NoteKey] = $"sessionsCutOff={cut.UtcDateTime:O}";
            return Results.NoContent();
        }).WithDescription("Sets the user's password. Unless it is the user's first password, the same write raises the user's session cut-off: every session and every access token without a session that was authenticated before it stops working, and a sign-in that began before it (for example one that had just verified the old password) cannot keep a session. The audit note carries sessionsCutOff=<time>. The user's version does not change."
            + " Guarantee for a token without a session: it is refused when its sign-in was stamped before the change committed, up to the store's clock reading taken as the last write of the change; a sign-in stamped in the few microseconds between that reading and the commit that still verified the old password is not caught and its token lives until exp (a session is always closed completely).");
        users.MapGet("/{id:guid}/sessions", (Guid id, SessionService s, IUserRepository u, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(id, u, PageQuery.Parse(limit, cursor), ct)).ProducesProblem(StatusCodes.Status404NotFound);
        users.MapGet("/{id:guid}/sessions/{sessionId:guid}", (Guid id, Guid sessionId, SessionService s, CancellationToken ct) =>
            s.GetForUserAsync(id, sessionId, ct))
            .WithDescription("404 both when there is no such session and when it belongs to another user. Any state (active, revoked or expired) is returned while the row is kept.")
            .ProducesProblem(StatusCodes.Status404NotFound);
        users.MapDelete("/{id:guid}/sessions/{sessionId:guid}", async (Guid id, Guid sessionId, SessionService s, CancellationToken ct) =>
        {
            await s.RevokeForUserAsync(id, sessionId, ct);
            return Results.NoContent();
        }).WithDescription("Ends one session of the user. 404 both when there is no such session and when it belongs to another user. The audit target names the user and session ids.")
          .Produces(StatusCodes.Status204NoContent)
          .ProducesProblem(StatusCodes.Status404NotFound);
        users.MapDelete("/{id:guid}/sessions", async (HttpContext http, Guid id, SessionService s, UserService u, AdminAccessCheck access, CancellationToken ct) =>
        {
            await u.GetAsync(id, ct); // 404 for an unknown user
            var (revoked, cutOff) = await s.RevokeAllAndCutOffAsync(id, ct);
            access.Evict(id);
            http.Items[AuditMiddleware.NoteKey] = $"revoked={revoked}; sessionsCutOff={cutOff.UtcDateTime:O}";
            return Results.Ok(new RevokedResponse(revoked));
        }).WithDescription("Ends all of the user's sessions and raises the user's session cut-off in one step: a sign-in that is still being completed, and access tokens without a session issued before now, are refused as well. The audit note carries sessionsCutOff=<time>. The user's version does not change.")
          .ProducesProblem(StatusCodes.Status404NotFound);
        users.MapGet("/{id:guid}/roles", (Guid id, UserService s, Guid? application, int? limit, string? cursor, CancellationToken ct) =>
            s.ListRoleViewsAsync(id, application, PageQuery.Parse(limit, cursor), ct))
            .WithDescription("Each item carries appName, the name of the role's application (read-only).");
        users.MapPut("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, UserService s, CancellationToken ct) =>
        {
            await s.AssignRoleAsync(id, roleId, ct);
            return Results.NoContent();
        });
        users.MapDelete("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, UserService s, CancellationToken ct) =>
        {
            await s.RevokeRoleAsync(id, roleId, ct);
            return Results.NoContent();
        }).WithDescription("When this was the user's last role in the application, the user's sessions in that application end at once (other applications are untouched).");

        var clients = v1.MapGroup("/clients").WithTags("Clients");
        clients.MapGet("/", (ClientService s, Guid? application, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(application, PageQuery.Parse(limit, cursor), ct));
        clients.MapPost("/", async (ClientRequest r, ClientService s, HttpContext http, CancellationToken ct) =>
        {
            if (r.Application is null) throw new ValidationException(new Dictionary<string, string> { ["application"] = "is required." });
            var created = await s.CreateAsync(r.Name, r.Application.Value, r.IsActive ?? true, ct);
            http.Response.Headers.CacheControl = "no-store"; // the body carries the one-time secret
            var c = created.Client;
            http.Items[AuditMiddleware.NoteKey] = $"client={c.Id} name={c.Name} application={c.AppId}"; // never the secret
            return Results.Created($"/v1/clients/{c.Id}",
                new ClientCreatedResponse(c.Id, c.Name, c.AppId, c.IsActive, c.CreatedAt, c.UpdatedAt, created.Secret, c.Version));
        }).Produces<ClientCreatedResponse>(StatusCodes.Status201Created);
        clients.MapGet("/{id:guid}", (Guid id, ClientService s, CancellationToken ct) => s.GetAsync(id, ct));
        clients.MapPut("/{id:guid}", (HttpContext http, Guid id, ClientRequest r, ClientService s, CancellationToken ct) => s.UpdateAsync(id, r.Name, r.IsActive, IfMatch(http), ct));
        clients.MapMethods("/{id:guid}", ["PATCH"], (HttpContext http, Guid id, ClientRequest r, ClientService s, CancellationToken ct) => s.PatchAsync(id, r.Name, r.IsActive, IfMatch(http), ct));
        clients.MapDelete("/{id:guid}", async (HttpContext http, Guid id, ClientService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, IfMatch(http), ct);
            return Results.NoContent();
        });
        clients.MapPost("/{id:guid}/secret", async (Guid id, ClientService s, HttpContext http, CancellationToken ct) =>
        {
            var secret = await s.RotateSecretAsync(id, ct);
            http.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new SecretResponse(secret));
        });
        clients.MapGet("/{id:guid}/roles", (Guid id, ClientService s, int? limit, string? cursor, CancellationToken ct) =>
            s.ListRolesAsync(id, PageQuery.Parse(limit, cursor), ct));
        clients.MapPut("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, ClientService s, CancellationToken ct) =>
        {
            await s.AssignRoleAsync(id, roleId, ct);
            return Results.NoContent();
        });
        clients.MapDelete("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, ClientService s, CancellationToken ct) =>
        {
            await s.RevokeRoleAsync(id, roleId, ct);
            return Results.NoContent();
        });

        v1.MapGet("/audit", (AuditService s, string? actor, string? action, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(actor, action, AuditPageQuery.Parse(limit, cursor), ct)).WithTags("Audit")
            .WithDescription("Newest first. The cursor is opaque and keyset-based (the last row's time and id): events arriving between pages cause no repeats or gaps. A cursor from another list, or an edited one, is 400.");
    }

    /// <summary>Self-service: the caller's own account and sessions. The subject always comes from the token, never from the URL.</summary>
    private static IResult Throttled(HttpContext http, TimeSpan wait)
    {
        http.Items[AuditMiddleware.SkipKey] = true;
        http.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
        return Results.Problem("Too many failed attempts. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
    }

    private static void MapMe(IEndpointRouteBuilder routes)
    {
        var me = routes.MapGroup("/v1/me").RequireAuthorization(SelfPolicy).WithTags("Me");
        static Guid UserId(HttpContext http) => AdminAccessCheck.Subject(http.User)!.Value.UserId;
        static Guid? SessionId(HttpContext http) => AdminAccessCheck.Subject(http.User)!.Value.SessionId;

        me.MapGet("/", async (HttpContext http, IUserRepository users, CancellationToken ct) =>
        {
            var u = await users.GetAsync(UserId(http), ct) ?? throw new NotFoundException("User not found.");
            http.Response.Headers.CacheControl = "no-store";
            return new MeResponse(u.Id, u.Username, u.DisplayName, u.Email, u.Kind, u.ExpiresAt);
        }).WithDescription("The caller's own account. Works with any token for the gatekeeper audience whose user is a usable person or test user (an administrator's token too).");
        me.MapGet("/sessions", async (HttpContext http, SessionService s, IUserRepository users, IAppRepository apps, int? limit, string? cursor, CancellationToken ct) =>
        {
            var current = SessionId(http);
            var page = await s.ListAsync(UserId(http), users, PageQuery.Parse(limit, cursor), ct);
            // Application names for the owner's own sessions (the admin application lookup is not open to a self token).
            var names = new Dictionary<Guid, string?>();
            foreach (var appId in page.Items.Select(x => x.AppId).Distinct())
                names[appId] = (await apps.GetAsync(appId, ct))?.Name;
            http.Response.Headers.CacheControl = "no-store";
            return new Page<OwnSession>(page.Items.Select(x => new OwnSession(x.Id, x.UserId, x.AppId, names[x.AppId], x.CreatedAt, x.LastUsedAt, x.ExpiresAt, x.RevokedAt, x.Id == current)).ToList(), page.NextCursor);
        }).WithDescription("The caller's own active sessions, newest first. current is true for the session the token came from (a token without a session has none).");
        me.MapDelete("/sessions/{id:guid}", async (HttpContext http, Guid id, SessionService s, AdminAccessCheck access, CancellationToken ct) =>
        {
            await s.RevokeForUserAsync(UserId(http), id, ct);
            access.Evict(UserId(http), id); // a token of the ended session stops at once, not after the 10 s cache
            return Results.NoContent();
        }).WithDescription("Ends one of the caller's own sessions (the current one too). 404 both when there is no such session and when it belongs to another user. 429 (with Retry-After, and no audit row) when the caller made more state-changing /v1/me calls than allowed in the last minute (Audit__MeWritesPerMinute, default 30).")
          .Produces(StatusCodes.Status204NoContent)
          .ProducesProblem(StatusCodes.Status404NotFound)
          .ProducesProblem(StatusCodes.Status429TooManyRequests);
        me.MapPut("/password", async (HttpContext http, OwnPasswordRequest r, CredentialService credentials, AdminAccessCheck access,
                [FromKeyedServices("passwordUser")] LoginThrottle userThrottle, [FromKeyedServices("passwordAddress")] LoginThrottle addressThrottle, CancellationToken ct) =>
            {
                var userId = UserId(http);
                var keep = SessionId(http);
                var address = (http.Connection.RemoteIpAddress ?? System.Net.IPAddress.None).ToString();
                var userKey = $"pw:{userId}";
                http.Response.Headers.CacheControl = "no-store";
                // Attempts are reserved atomically BEFORE any hashing (parallel requests cannot all pass a check made before the first
                // failure is recorded). A slot stays taken, i.e. counts as a failed guess, unless the attempt succeeded or was not a guess.
                // A throttled attempt writes no audit row: the attempts that filled the window were recorded (bounded by the limits).
                if (!userThrottle.TryReserve(userKey, out var userWait))
                    return Throttled(http, userWait);
                if (!addressThrottle.TryReserve(address, out var addressWait))
                {
                    userThrottle.Release(userKey);
                    return Throttled(http, addressWait);
                }

                OwnPasswordChange change;
                try
                {
                    change = await credentials.ChangeOwnPasswordAsync(userId, r.CurrentPassword, r.NewPassword, keep, ct);
                }
                catch (ValidationException)
                {
                    // Rule violations are decided before the current password is looked at: they cannot be a guess, so the owner's own typos
                    // do not use up the per-user limit. They still count per address, which bounds a flood of malformed requests.
                    userThrottle.Release(userKey);
                    throw;
                }
                catch (BusyException busy) when (busy.AfterVerification)
                {
                    // The current password was verified (a guess was spent) and the write could not run: keep both throttle slots, so these
                    // rows are bounded by the same limits, and let the audit middleware record the failure.
                    http.Items[AuditMiddleware.NoteKey] = "reason=busy";
                    throw;
                }
                catch (BusyException)
                {
                    // Nothing was decided; hand the slots back and write no audit row (a 503 flood must not become an audit flood).
                    userThrottle.Release(userKey);
                    addressThrottle.Release(address);
                    http.Items[AuditMiddleware.SkipKey] = true;
                    throw;
                }
                switch (change.Result)
                {
                    case OwnPasswordResult.WrongCurrent:
                        http.Items[AuditMiddleware.SelfAuditedKey] = true; // the audit middleware writes the one failure row; no extra "forbidden" row
                        http.Items[AuditMiddleware.NoteKey] = "reason=current-password";
                        // 403, not 401: a client must not read this as an expired token and sign the user out.
                        return Results.Problem(WrongCurrentPasswordText, statusCode: StatusCodes.Status403Forbidden,
                            extensions: new Dictionary<string, object?> { ["code"] = WrongCurrentPasswordCode });
                    case OwnPasswordResult.Unchanged:
                        // Only reached after the current password verified, so it is not a guess: per-address only.
                        userThrottle.Release(userKey);
                        http.Items[AuditMiddleware.NoteKey] = "reason=same-password";
                        return Results.ValidationProblem(new Dictionary<string, string[]> { ["newPassword"] = ["must differ from the current password."] });
                }

                userThrottle.Release(userKey);
                addressThrottle.Release(address);
                access.Evict(userId); // every token of the user's ended sessions stops at once on this instance
                http.Items[AuditMiddleware.NoteKey] = $"sessionsRevoked={change.SessionsRevoked}; kept={(keep is { } k ? k.ToString() : "none")}"
                    + (change.CutOff is { } cut ? $"; sessionsCutOff={cut.UtcDateTime:O}" : "");
                return Results.NoContent();
            })
          .WithDescription("Changes the caller's own password. Needs the current password (verified like a login). 204: changed; every other session of the user ended (all of them for a token without a session, which then ends too), the session of the token is kept, and the user's session cut-off is raised in the same write (a sign-in that began before it cannot keep a session). 400: the new password breaks the password rules or equals the current one. 403 with code current-password-incorrect: the current password was not accepted (a fixed answer, deliberately not 401, so clients do not treat it as an ended session). 429: too many failed attempts for this user or address, or too many state-changing /v1/me calls in the last minute (Retry-After). Neither password is ever logged or audited; the audit row has the route and the number of sessions ended.")
          .Produces(StatusCodes.Status204NoContent)
          .ProducesProblem(StatusCodes.Status400BadRequest)
          .ProducesProblem(StatusCodes.Status403Forbidden)
          .ProducesProblem(StatusCodes.Status429TooManyRequests);
        me.MapDelete("/sessions", async (HttpContext http, SessionService s, IUserRepository users, AdminAccessCheck access, CancellationToken ct) =>
            {
                var keep = SessionId(http);
                var before = await s.ListAsync(UserId(http), users, new PageQuery(0, PageQuery.MaxLimit), ct);
                var revoked = await s.RevokeAllExceptAsync(UserId(http), keep, ct);
                foreach (var x in before.Items.Where(x => x.Id != keep)) access.Evict(x.UserId, x.Id);
                http.Items[AuditMiddleware.NoteKey] = $"revoked={revoked}; kept={(keep is { } k ? k.ToString() : "none")}";
                return Results.Ok(new RevokedResponse(revoked));
            })
          .WithDescription("Ends all of the caller's other active sessions; the session of the token stays (it ends by signing out or DELETE /v1/me/sessions/{id}). 429 (with Retry-After, and no audit row) when the caller made more state-changing /v1/me calls than allowed in the last minute (Audit__MeWritesPerMinute, default 30).")
          .Produces<RevokedResponse>(StatusCodes.Status200OK)
          .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }
}
