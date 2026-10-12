using System.Net.Http.Headers;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

public static class TestAuth
{
    /// <summary>A client carrying a valid administrator token minted by the factory's own TokenService.</summary>
    public static HttpClient CreateAdminClient(this WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AdminToken(factory));
        return client;
    }

    public static string AdminToken(WebApplicationFactory<Program> factory) => Token(factory, Reserved.AdminApp, [Reserved.AdminRole]);

    public static string Token(WebApplicationFactory<Program> factory, string audience, string[] roles, DateTimeOffset? now = null)
    {
        var tokens = factory.Services.GetRequiredService<TokenService>();
        var user = new User(Guid.NewGuid(), "test-admin", "test-admin@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        return tokens.Issue(new AuthResult(user, new App(Guid.NewGuid(), audience), roles), now).Token;
    }
}
