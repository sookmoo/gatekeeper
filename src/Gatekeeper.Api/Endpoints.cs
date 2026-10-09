using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

public sealed record AppRequest(string? Name);

public sealed record RoleRequest(string? Name, string? Description);

public sealed record UserRequest(string? Username, string? Email, string? DisplayName, bool? IsActive);

public static class Endpoints
{
    public static void MapApi(this IEndpointRouteBuilder routes)
    {
        var v1 = routes.MapGroup("/v1");

        var apps = v1.MapGroup("/applications").WithTags("Applications");
        apps.MapGet("/", (AppService s) => s.ListAsync());
        apps.MapPost("/", async (AppRequest r, AppService s) =>
        {
            var created = await s.CreateAsync(r.Name);
            return Results.Created($"/v1/applications/{created.Id}", created);
        });
        apps.MapGet("/{id:guid}", (Guid id, AppService s) => s.GetAsync(id));
        apps.MapPut("/{id:guid}", (Guid id, AppRequest r, AppService s) => s.UpdateAsync(id, r.Name));
        apps.MapDelete("/{id:guid}", async (Guid id, AppService s) =>
        {
            await s.DeleteAsync(id);
            return Results.NoContent();
        });
        apps.MapGet("/{id:guid}/roles", (Guid id, RoleService s) => s.ListByAppAsync(id));
        apps.MapPost("/{id:guid}/roles", async (Guid id, RoleRequest r, RoleService s) =>
        {
            var created = await s.CreateAsync(id, r.Name, r.Description);
            return Results.Created($"/v1/roles/{created.Id}", created);
        });

        var roles = v1.MapGroup("/roles").WithTags("Roles");
        roles.MapGet("/{id:guid}", (Guid id, RoleService s) => s.GetAsync(id));
        roles.MapPut("/{id:guid}", (Guid id, RoleRequest r, RoleService s) => s.UpdateAsync(id, r.Name, r.Description));
        roles.MapDelete("/{id:guid}", async (Guid id, RoleService s) =>
        {
            await s.DeleteAsync(id);
            return Results.NoContent();
        });

        var users = v1.MapGroup("/users").WithTags("Users");
        users.MapGet("/", (UserService s, bool? active, string? username) => s.ListAsync(active, username));
        users.MapPost("/", async (UserRequest r, UserService s) =>
        {
            var created = await s.CreateAsync(r.Username, r.Email, r.DisplayName, r.IsActive ?? true);
            return Results.Created($"/v1/users/{created.Id}", created);
        });
        users.MapGet("/{id:guid}", (Guid id, UserService s) => s.GetAsync(id));
        users.MapPut("/{id:guid}", (Guid id, UserRequest r, UserService s) =>
            s.UpdateAsync(id, r.Username, r.Email, r.DisplayName, r.IsActive ?? true));
        users.MapDelete("/{id:guid}", async (Guid id, UserService s) =>
        {
            await s.DeleteAsync(id);
            return Results.NoContent();
        });
        users.MapGet("/{id:guid}/roles", (Guid id, UserService s, Guid? application) => s.ListRolesAsync(id, application));
        users.MapPut("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, UserService s) =>
        {
            await s.AssignRoleAsync(id, roleId);
            return Results.NoContent();
        });
        users.MapDelete("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, UserService s) =>
        {
            await s.RevokeRoleAsync(id, roleId);
            return Results.NoContent();
        });
    }
}
