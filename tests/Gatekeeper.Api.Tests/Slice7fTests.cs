using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 7f: Auth__AccessCheckCacheSeconds (0 to 10, default 10; 0 = no cache).</summary>
public class Slice7fTests
{
    private static WebApplicationFactory<Program> Factory(string? seconds) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            if (seconds is not null) b.UseSetting("Auth:AccessCheckCacheSeconds", seconds);
        });

    /// <summary>Checks the administrator, deactivates them behind the cache's back and returns the answer afterwards.</summary>
    private static async Task<AccessState?> AnswerAfterDeactivation(WebApplicationFactory<Program> f)
    {
        var admin = TestAuth.EnsureAdmin(f);
        var access = f.Services.GetRequiredService<AdminAccessCheck>();
        Assert.True((await access.StateAsync(admin.Id, null, default))!.IsAdmin);
        var users = f.Services.GetRequiredService<IUserRepository>();
        Assert.NotNull(await users.UpdateAsync(admin with { IsActive = false }));
        return await access.StateAsync(admin.Id, null, default);
    }

    [Fact]
    public async Task Zero_shows_a_deactivation_at_once()
    {
        using var f = Factory("0");
        Assert.Equal(TimeSpan.Zero, f.Services.GetRequiredService<AdminAccessCheck>().CacheFor);
        Assert.Null(await AnswerAfterDeactivation(f));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("10")]
    public async Task Ten_and_the_default_keep_the_answer_for_ten_seconds(string? seconds)
    {
        using var f = Factory(seconds);
        Assert.Equal(TimeSpan.FromSeconds(10), f.Services.GetRequiredService<AdminAccessCheck>().CacheFor);
        Assert.NotNull(await AnswerAfterDeactivation(f)); // still the cached answer
    }

    [Fact]
    public void A_value_between_keeps_its_length()
    {
        using var f = Factory("3");
        Assert.Equal(TimeSpan.FromSeconds(3), f.Services.GetRequiredService<AdminAccessCheck>().CacheFor);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("11")]
    [InlineData("abc")]
    public void Invalid_values_stop_the_start(string value)
    {
        using var f = Factory(value);
        Assert.ThrowsAny<Exception>(() => f.CreateClient());
    }
}
