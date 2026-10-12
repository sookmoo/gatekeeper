using System.Collections.Concurrent;
using System.Net.Http.Headers;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

public static class TestAuth
{
    public const string AdminName = "test-admin";
    public const string AdminPassword = "a test admin password";

    private static readonly ConcurrentDictionary<IServiceProvider, SemaphoreSlim> Gates = new();

    /// <summary>A client carrying a valid administrator token minted by the factory's own TokenService.</summary>
    public static HttpClient CreateAdminClient(this WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AdminToken(factory));
        return client;
    }

    /// <summary>Makes sure the reserved admin app/role and a real administrator exist in the factory's store.</summary>
    public static User EnsureAdmin(WebApplicationFactory<Program> factory)
    {
        var services = factory.Services;
        var gate = Gates.GetOrAdd(services, _ => new SemaphoreSlim(1, 1));
        gate.Wait();
        try
        {
            var users = services.GetRequiredService<IUserRepository>();
            var existing = users.ListAsync(username: AdminName, slice: new Slice(0, 1)).GetAwaiter().GetResult().FirstOrDefault();
            if (existing is not null) return existing;
            Bootstrap.CreateAdminAsync(services, AdminName, "test-admin@example.com", AdminPassword).GetAwaiter().GetResult();
            return users.ListAsync(username: AdminName, slice: new Slice(0, 1)).GetAwaiter().GetResult().Single();
        }
        finally
        {
            gate.Release();
        }
    }

    public static string AdminToken(WebApplicationFactory<Program> factory)
    {
        var admin = EnsureAdmin(factory);
        return Mint(factory, admin, Reserved.AdminApp, [Reserved.AdminRole]);
    }

    /// <summary>Mints a token for any user and claims, signed with the factory's real key (the store is not consulted).</summary>
    public static string Mint(WebApplicationFactory<Program> factory, User user, string audience, string[] roles, DateTimeOffset? now = null) =>
        factory.Services.GetRequiredService<TokenService>().Issue(new AuthResult(user, new App(Guid.NewGuid(), audience), roles), now).Token;

    /// <summary>A token for a user that exists nowhere in the store.</summary>
    public static string Token(WebApplicationFactory<Program> factory, string audience, string[] roles, DateTimeOffset? now = null) =>
        Mint(factory, new User(Guid.NewGuid(), "ghost", "ghost@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), audience, roles, now);
}
