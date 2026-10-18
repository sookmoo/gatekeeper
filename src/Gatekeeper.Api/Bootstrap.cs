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
        var role = (await roles.ListByAppAsync(app.Id)).FirstOrDefault(r => Reserved.IsAdminRole(r.Name))
                   ?? await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, Reserved.AdminRole, "Manages Gatekeeper"));
        // Older code may have stored "ADMIN"; the policy matches exactly, so repair the name.
        if (role.Name != Reserved.AdminRole)
            role = await roles.UpdateAsync(role with { Name = Reserved.AdminRole }) ?? throw new NotFoundException("The admin role disappeared.");
        var existing = (await services.GetRequiredService<IUserRepository>().ListAsync(username: username, slice: new Slice(0, 1))).FirstOrDefault();
        // Refuse before changing anything: the admin role is for people only.
        if (existing is { Kind: not UserKind.Person })
            throw new ConflictException($"User '{username}' is a {existing.Kind.ToString().ToLowerInvariant()} account and cannot be an administrator. Change its kind to person first, or pick another name.");
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
            try
            {
                await services.GetRequiredService<AuditRecorder>().RecordAsync("system", "bootstrap-admin", username, true, created ? "created" : "repaired");
            }
            catch (Exception ex) when (ex is GatekeeperException or InvalidOperationException)
            {
                Console.Error.WriteLine($"warning: could not write the audit event: {ex.GetType().Name}");
            }
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
