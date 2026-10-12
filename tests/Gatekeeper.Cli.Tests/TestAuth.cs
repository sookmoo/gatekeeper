using System.Net.Http.Headers;
using Gatekeeper.Api;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Cli.Tests;

internal static class TestAuth
{
    public const string AdminName = "test-admin";
    public const string AdminPassword = "a test admin password";

    private static readonly object Lock = new();

    public static HttpClient CreateAdminClient(this WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AdminToken(factory));
        return client;
    }

    public static string AdminToken(WebApplicationFactory<Program> factory)
    {
        var services = factory.Services;
        User admin;
        lock (Lock)
        {
            var users = services.GetRequiredService<IUserRepository>();
            admin = users.ListAsync(username: AdminName, slice: new Slice(0, 1)).GetAwaiter().GetResult().FirstOrDefault()
                    ?? CreateAdmin(services);
        }
        return services.GetRequiredService<TokenService>()
            .Issue(new AuthResult(admin, new App(Guid.NewGuid(), Reserved.AdminApp), [Reserved.AdminRole])).Token;
    }

    private static User CreateAdmin(IServiceProvider services)
    {
        Bootstrap.CreateAdminAsync(services, AdminName, "test-admin@example.com", AdminPassword).GetAwaiter().GetResult();
        return services.GetRequiredService<IUserRepository>().ListAsync(username: AdminName, slice: new Slice(0, 1)).GetAwaiter().GetResult().Single();
    }
}
