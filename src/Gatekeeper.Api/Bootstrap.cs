using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

/// <summary>Creates the admin application, its admin role and the first administrator. Refuses if the user exists.</summary>
public static class Bootstrap
{
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

            var apps = services.GetRequiredService<IAppRepository>();
            var roles = services.GetRequiredService<IRoleRepository>();
            var users = services.GetRequiredService<UserService>();
            var credentials = services.GetRequiredService<CredentialService>();

            if ((await services.GetRequiredService<IUserRepository>().ListAsync(username: username, slice: new Slice(0, 1))).Count > 0)
            {
                Console.Error.WriteLine($"error: user '{username}' already exists; nothing changed.");
                return 1;
            }

            var app = await apps.GetByNameAsync(Reserved.AdminApp) ?? await apps.AddAsync(new App(Guid.NewGuid(), Reserved.AdminApp));
            var role = (await roles.ListByAppAsync(app.Id)).FirstOrDefault(r => r.Name == Reserved.AdminRole)
                       ?? await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, Reserved.AdminRole, "Manages Gatekeeper"));
            var user = await users.CreateAsync(username, email, username);
            await credentials.SetPasswordAsync(user.Id, password);
            await services.GetRequiredService<UserService>().AssignRoleAsync(user.Id, role.Id);
            Console.WriteLine($"Administrator '{username}' created.");
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
