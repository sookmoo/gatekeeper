using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

/// <summary>
/// Creates the admin application, its admin role and an administrator. If the user already exists this repairs it:
/// reactivates, resets the password and re-assigns the admin role (the recovery path when the last admin is locked out).
/// </summary>
public static class Bootstrap
{
    /// <summary>Ensures the admin app and role exist, then creates the user with the password and the admin role.</summary>
    public static async Task<bool> CreateAdminAsync(IServiceProvider services, string username, string email, string password)
    {
        var apps = services.GetRequiredService<IAppRepository>();
        var roles = services.GetRequiredService<IRoleRepository>();
        var users = services.GetRequiredService<UserService>();
        var app = await apps.GetByNameAsync(Reserved.AdminApp) ?? await apps.AddAsync(new App(Guid.NewGuid(), Reserved.AdminApp));
        var role = (await roles.ListByAppAsync(app.Id)).FirstOrDefault(r => r.Name == Reserved.AdminRole)
                   ?? await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, Reserved.AdminRole, "Manages Gatekeeper"));
        var existing = (await services.GetRequiredService<IUserRepository>().ListAsync(username: username, slice: new Slice(0, 1))).FirstOrDefault();
        var user = existing ?? await users.CreateAsync(username, email, username);
        if (existing is { IsActive: false })
            await users.UpdateAsync(existing.Id, existing.Username, existing.Email, existing.DisplayName, true);
        await services.GetRequiredService<CredentialService>().SetPasswordAsync(user.Id, password);
        await users.AssignRoleAsync(user.Id, role.Id);
        return existing is null;
    }

    public static async Task<int> RunAsync(IServiceProvider services, string username, string email)
    {
        try
        {
            var password = Environment.GetEnvironmentVariable("GATEKEEPER_BOOTSTRAP_PASSWORD");
            if (string.IsNullOrEmpty(password))
            {
                if (!Console.IsInputRedirected)
                {
                    Console.Error.WriteLine("error: pass the password on stdin or in GATEKEEPER_BOOTSTRAP_PASSWORD.");
                    return 1;
                }
                password = (await Console.In.ReadLineAsync())?.TrimEnd('\r', '\n');
            }
            Validation.Password(password);
            Validation.UserFields(username, email, null);

            var created = await CreateAdminAsync(services, username, email, password!);
            Console.WriteLine(created
                ? $"Administrator '{username}' created."
                : $"Administrator '{username}' already existed: reactivated, password reset, admin role ensured.");
            return 0;
        }
        catch (ValidationException ex)
        {
            Console.Error.WriteLine("error: " + string.Join("; ", ex.Errors.Select(e => $"{e.Key} {e.Value}")));
            return 1;
        }
        catch (GatekeeperException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }
}
