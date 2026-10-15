using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class UserKindCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public UserKindCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(params string[] args)
    {
        TestAuth.AdminToken(_factory);
        var o = new StringWriter(); var e = new StringWriter();
        var tokens = new MemoryTokenStore();
        var login = await CliApp.RunAsync(["login", "--user", TestAuth.AdminName], _ => _factory.CreateClient(), new StringWriter(), new StringWriter(), tokens, (_, _) => TestAuth.AdminPassword);
        Assert.Equal(0, login);
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => null);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Users_can_be_created_listed_and_changed_by_kind()
    {
        var name = $"cli-{Guid.NewGuid():N}"[..16];
        var created = await Gk("user", "create", name, "--email", $"{name}@example.com", "--kind", "test", "--expires", DateTime.UtcNow.AddDays(10).ToString("yyyy-MM-dd"));
        Assert.Equal(0, created.Code);
        Assert.Contains("test", created.Out);

        var listed = await Gk("user", "list", "--kind", "test");
        Assert.Equal(0, listed.Code);
        Assert.Contains(name, listed.Out);
        Assert.DoesNotContain(name, (await Gk("user", "list", "--kind", "person")).Out);

        var back = await Gk("user", "update", name, "--kind", "person");
        Assert.Equal(0, back.Code);
        Assert.Contains("person", back.Out);
        Assert.NotEqual(0, (await Gk("user", "list", "--kind", "robot")).Code);
    }
}
