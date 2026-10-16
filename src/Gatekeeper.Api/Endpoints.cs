using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

public sealed record AppRequest(string? Name);

public sealed record RoleRequest(string? Name, string? Description);

public sealed record UserRequest(string? Username, string? Email, string? DisplayName, bool? IsActive, UserKind? Kind = null, DateTimeOffset? ExpiresAt = null);

public sealed record ClientRequest(string? Name, Guid? Application, bool? IsActive);

public sealed record ClientCreatedResponse(Guid Id, string Name, Guid AppId, bool IsActive, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, string Secret);

public sealed record RevokedResponse(int Revoked);

public sealed record SecretResponse(string Secret);

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
        http.Items[AuditMiddleware.NoteKey] = $"kind={u.Kind.ToString().ToLowerInvariant()} expiresAt={(u.ExpiresAt is { } e ? e.UtcDateTime.ToString("O") : "none")} active={u.IsActive}";
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
            Noted(http, s.UpdateAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, r.Kind, r.ExpiresAt, ct)));
        users.MapMethods("/{id:guid}", ["PATCH"], (HttpContext http, Guid id, UserRequest r, UserService s, CancellationToken ct) =>
            Noted(http, s.PatchAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, r.Kind, r.ExpiresAt, ct)));
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
        });

        v1.MapGroup("/sessions").WithTags("Sessions").MapDelete("/{id:guid}", async (Guid id, SessionService s, CancellationToken ct) =>
        {
            await s.RevokeAsync(id, ct);
            return Results.NoContent();
        }).ProducesProblem(StatusCodes.Status404NotFound);

        var clients = v1.MapGroup("/clients").WithTags("Clients");
        clients.MapGet("/", (ClientService s, Guid? application, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(application, PageQuery.Parse(limit, cursor), ct));
        clients.MapPost("/", async (ClientRequest r, ClientService s, HttpContext http, CancellationToken ct) =>
        {
            if (r.Application is null) throw new ValidationException(new Dictionary<string, string> { ["application"] = "is required." });
            var created = await s.CreateAsync(r.Name, r.Application.Value, r.IsActive ?? true, ct);
            http.Response.Headers.CacheControl = "no-store"; // the body carries the one-time secret
            var c = created.Client;
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
            s.ListAsync(actor, action, PageQuery.Parse(limit, cursor), ct)).WithTags("Audit");
    }
}
