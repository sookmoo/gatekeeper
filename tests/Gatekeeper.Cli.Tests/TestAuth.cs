using System.Net.Http.Headers;
using Gatekeeper.Api;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Cli.Tests;

internal static class TestAuth
{
    public static HttpClient CreateAdminClient(this WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AdminToken(factory));
        return client;
    }

    public static string AdminToken(WebApplicationFactory<Program> factory)
    {
        var user = new User(Guid.NewGuid(), "test-admin", "test-admin@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        return factory.Services.GetRequiredService<TokenService>()
            .Issue(new AuthResult(user, new App(Guid.NewGuid(), Reserved.AdminApp), [Reserved.AdminRole])).Token;
    }
}
