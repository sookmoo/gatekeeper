using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

public sealed record AppRequest(string? Name);

public sealed record RoleRequest(string? Name, string? Description);

public sealed record UserRequest(string? Username, string? Email, string? DisplayName, bool? IsActive, UserKind? Kind = null, DateTimeOffset? ExpiresAt = null);

public sealed record ClientRequest(string? Name, Guid? Application, bool? IsActive);

/// <summary>A new client with its one-time secret. ToString never prints the secret, so logging the object cannot leak it.</summary>
public sealed record ClientCreatedResponse(Guid Id, string Name, Guid AppId, bool IsActive, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, string Secret)
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

public static class Endpoints
{
    public const string AdminPolicy = "admin";

    /// <summary>Exactly person, test or shared (any case): not numbers and not comma lists, which Enum.TryParse would accept.</summary>
    private static UserKind? ParseKind(string? kind) =>
        string.IsNullOrEmpty(kind) ? null
        : kind.Equals("person", StringComparison.OrdinalIgnoreCase) ? UserKind.Person
        : kind.Equals("test", StringComparison.OrdinalIgnoreCase) ? UserKind.Test
        : kind.Equals("shared", StringComparison.OrdinalIgnoreCase) ? UserKind.Shared
        : throw new ValidationException(new Dictionary<string, string> { ["kind"] = "must be person, test or shared." });

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
        var note = UserNote(u);
        if (fx.Revoked > 0) note += $" sessionsRevoked={fx.Revoked}";
        if (fx.Capped > 0) note += $" sessionsCapped={fx.Capped}";
        http.Items[AuditMiddleware.NoteKey] = note;
        return u;
    }

    public static void MapApi(this IEndpointRouteBuilder routes)
    {
        var v1 = routes.MapGroup("/v1").RequireAuthorization(AdminPolicy);

        var apps = v1.MapGroup("/applications").WithTags("Applications");
        apps.MapGet("/", (AppService s, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(PageQuery.Parse(limit, cursor), ct));
        apps.MapPost("/", async (AppRequest r, AppService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(r.Name, ct);
            return Results.Created($"/v1/applications/{created.Id}", created);
        });
        apps.MapGet("/{id:guid}", (Guid id, AppService s, CancellationToken ct) => s.GetAsync(id, ct));
        apps.MapPut("/{id:guid}", (Guid id, AppRequest r, AppService s, CancellationToken ct) => s.UpdateAsync(id, r.Name, ct));
        apps.MapMethods("/{id:guid}", ["PATCH"], (Guid id, AppRequest r, AppService s, CancellationToken ct) => s.PatchAsync(id, r.Name, ct));
        apps.MapDelete("/{id:guid}", async (Guid id, AppService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, ct);
            return Results.NoContent();
        });
        apps.MapGet("/{id:guid}/roles", (Guid id, RoleService s, int? limit, string? cursor, CancellationToken ct) =>
            s.ListByAppAsync(id, PageQuery.Parse(limit, cursor), ct));
        apps.MapPost("/{id:guid}/roles", async (Guid id, RoleRequest r, RoleService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(id, r.Name, r.Description, ct);
            return Results.Created($"/v1/roles/{created.Id}", created);
        });

        var roles = v1.MapGroup("/roles").WithTags("Roles");
        roles.MapGet("/{id:guid}", (Guid id, RoleService s, CancellationToken ct) => s.GetAsync(id, ct));
        roles.MapPut("/{id:guid}", (Guid id, RoleRequest r, RoleService s, CancellationToken ct) => s.UpdateAsync(id, r.Name, r.Description, ct));
        roles.MapMethods("/{id:guid}", ["PATCH"], (Guid id, RoleRequest r, RoleService s, CancellationToken ct) => s.PatchAsync(id, r.Name, r.Description, ct));
        roles.MapDelete("/{id:guid}", async (Guid id, RoleService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, ct);
            return Results.NoContent();
        });

        var users = v1.MapGroup("/users").WithTags("Users");
        users.MapGet("/", (UserService s, bool? active, string? username, string? kind, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(active, username, ParseKind(kind), PageQuery.Parse(limit, cursor), ct));
        users.MapPost("/", async (HttpContext http, UserRequest r, UserService s, CancellationToken ct) =>
        {
            var created = await Noted(http, s.CreateAsync(r.Username, r.Email, r.DisplayName, r.IsActive ?? true, r.Kind ?? UserKind.Person, r.ExpiresAt, ct));
            return Results.Created($"/v1/users/{created.Id}", created);
        });
        users.MapGet("/{id:guid}", (Guid id, UserService s, CancellationToken ct) => s.GetAsync(id, ct));
        users.MapPut("/{id:guid}", (HttpContext http, Guid id, UserRequest r, UserService s, CancellationToken ct) =>
            Noted(http, s.UpdateWithEffectsAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, r.Kind, r.ExpiresAt, ct)))
            .WithDescription("Setting isActive from true to false ends all of the user's sessions at once. Moving a test user's expiresAt earlier (or making a person a test user) caps active sessions to the new expiry; a later extension does not lengthen them.");
        users.MapMethods("/{id:guid}", ["PATCH"], (HttpContext http, Guid id, UserRequest r, UserService s, CancellationToken ct) =>
            Noted(http, s.PatchWithEffectsAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, r.Kind, r.ExpiresAt, ct)))
            .WithDescription("Setting isActive from true to false ends all of the user's sessions at once. Moving a test user's expiresAt earlier (or making a person a test user) caps active sessions to the new expiry; a later extension does not lengthen them.");
        users.MapDelete("/{id:guid}", async (Guid id, UserService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, ct);
            return Results.NoContent();
        });
        users.MapPut("/{id:guid}/password", async (Guid id, PasswordRequest r, CredentialService s, CancellationToken ct) =>
        {
            await s.SetPasswordAsync(id, r.Password, ct);
            return Results.NoContent();
        });
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
        users.MapDelete("/{id:guid}/sessions", async (Guid id, SessionService s, UserService u, CancellationToken ct) =>
        {
            await u.GetAsync(id, ct); // 404 for an unknown user
            return Results.Ok(new RevokedResponse(await s.RevokeAllAsync(id, ct)));
        }).ProducesProblem(StatusCodes.Status404NotFound);
        users.MapGet("/{id:guid}/roles", (Guid id, UserService s, Guid? application, int? limit, string? cursor, CancellationToken ct) =>
            s.ListRolesAsync(id, application, PageQuery.Parse(limit, cursor), ct));
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

        v1.MapGroup("/sessions").WithTags("Sessions").MapDelete("/{id:guid}", async (Guid id, SessionService s, HttpContext http, CancellationToken ct) =>
        {
            http.Response.Headers["Deprecation"] = "true";
            var owner = await s.RevokeAsync(id, ct);
            http.Response.Headers.Link = $"</v1/users/{owner}/sessions/{id}>; rel=\"successor-version\"";
            http.Items[AuditMiddleware.NoteKey] = $"user={owner}";
            return Results.NoContent();
        }).WithDescription("Deprecated: use DELETE /v1/users/{id}/sessions/{sessionId}, which is scoped to the owner. The audit note names the owner (user=<id>). The response carries a Deprecation header and a Link to the successor route; it will be removed once no client uses it.")
          .ProducesProblem(StatusCodes.Status404NotFound);

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
                new ClientCreatedResponse(c.Id, c.Name, c.AppId, c.IsActive, c.CreatedAt, c.UpdatedAt, created.Secret));
        });
        clients.MapGet("/{id:guid}", (Guid id, ClientService s, CancellationToken ct) => s.GetAsync(id, ct));
        clients.MapPut("/{id:guid}", (Guid id, ClientRequest r, ClientService s, CancellationToken ct) => s.UpdateAsync(id, r.Name, r.IsActive, ct));
        clients.MapMethods("/{id:guid}", ["PATCH"], (Guid id, ClientRequest r, ClientService s, CancellationToken ct) => s.PatchAsync(id, r.Name, r.IsActive, ct));
        clients.MapDelete("/{id:guid}", async (Guid id, ClientService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, ct);
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
}
