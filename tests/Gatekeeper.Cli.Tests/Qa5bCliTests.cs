using System.Globalization;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class Qa5bCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public Qa5bCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(params string[] args)
    {
        TestAuth.AdminToken(_factory);
        var o = new StringWriter(); var e = new StringWriter();
        var tokens = new MemoryTokenStore();
        Assert.Equal(0, await CliApp.RunAsync(["login", "--user", TestAuth.AdminName], _ => _factory.CreateClient(), new StringWriter(), new StringWriter(), tokens, (_, _) => TestAuth.AdminPassword));
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => null);
        return (code, o.ToString(), e.ToString());
    }

    private static string N() => $"q5-{Guid.NewGuid():N}"[..16];

    [Fact]
    public async Task A_past_expiry_is_a_nonzero_exit_with_a_message()
    {
        var n = N();
        var r = await Gk("user", "create", n, "--email", $"{n}@example.com", "--kind", "test", "--expires", "2020-01-01");
        Assert.NotEqual(0, r.Code);
        Assert.Contains("expiresAt", r.Err);
    }

    [Fact]
    public async Task Expires_on_a_person_is_refused()
    {
        var n = N();
        var r = await Gk("user", "create", n, "--email", $"{n}@example.com", "--expires", DateTime.UtcNow.AddDays(3).ToString("yyyy-MM-dd"));
        Assert.NotEqual(0, r.Code);
    }

    [Fact]
    public async Task An_unparsable_expiry_is_a_usage_error_not_a_crash()
    {
        var n = N();
        var r = await Gk("user", "create", n, "--email", $"{n}@example.com", "--kind", "test", "--expires", "next tuesday");
        Assert.NotEqual(0, r.Code);
        Assert.DoesNotContain("Unhandled", r.Err);
    }

    [Fact]
    public async Task Update_with_only_expires_on_a_test_user_extends_it()
    {
        var n = N();
        Assert.Equal(0, (await Gk("user", "create", n, "--email", $"{n}@example.com", "--kind", "test")).Code);
        var want = DateTime.UtcNow.AddDays(100).ToString("yyyy-MM-dd");
        var r = await Gk("user", "update", n, "--expires", want);
        Assert.Equal(0, r.Code);
        Assert.Contains(want[..7], r.Out);
    }
}
