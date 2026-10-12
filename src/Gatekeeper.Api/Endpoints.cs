using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

public sealed record AppRequest(string? Name);

public sealed record RoleRequest(string? Name, string? Description);

public sealed record UserRequest(string? Username, string? Email, string? DisplayName, bool? IsActive);

public sealed record PasswordRequest(string? Password);

public static class Endpoints
{
    public static void MapApi(this IEndpointRouteBuilder routes)
    {
        var v1 = routes.MapGroup("/v1");

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
        roles.MapDelete("/{id:guid}", async (Guid id, RoleService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, ct);
            return Results.NoContent();
        });

        var users = v1.MapGroup("/users").WithTags("Users");
        users.MapGet("/", (UserService s, bool? active, string? username, int? limit, string? cursor, CancellationToken ct) =>
            s.ListAsync(active, username, PageQuery.Parse(limit, cursor), ct));
        users.MapPost("/", async (UserRequest r, UserService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(r.Username, r.Email, r.DisplayName, r.IsActive ?? true, ct);
            return Results.Created($"/v1/users/{created.Id}", created);
        });
        users.MapGet("/{id:guid}", (Guid id, UserService s, CancellationToken ct) => s.GetAsync(id, ct));
        users.MapPut("/{id:guid}", (Guid id, UserRequest r, UserService s, CancellationToken ct) =>
            s.UpdateAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive, ct));
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
    }
}
