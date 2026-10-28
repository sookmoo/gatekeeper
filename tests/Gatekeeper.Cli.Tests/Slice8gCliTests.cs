using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class Slice8gCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public Slice8gCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

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
    public async Task User_list_filters_by_prefixes_and_usable()
    {
        var t = Guid.NewGuid().ToString("N")[..8];
        Assert.Equal(0, (await Gk("user", "create", $"cp{t}-ann", "--email", $"Ann.{t}@example.com")).Code);
        Assert.Equal(0, (await Gk("user", "create", $"cp{t}-bea", "--email", $"bea{t}@example.com")).Code);
        Assert.Equal(0, (await Gk("user", "create", $"cp{t}-off", "--email", $"off{t}@example.com", "--inactive")).Code);

        var byName = await Gk("user", "list", "--prefix", $"CP{t}-A");
        Assert.Equal(0, byName.Code);
        Assert.Contains($"cp{t}-ann", byName.Out);
        Assert.DoesNotContain($"cp{t}-bea", byName.Out);

        var byEmail = await Gk("user", "list", "--email-prefix", $"ann.{t}");
        Assert.Contains($"cp{t}-ann", byEmail.Out);
        Assert.DoesNotContain($"cp{t}-bea", byEmail.Out);

        var usable = await Gk("user", "list", "--prefix", $"cp{t}", "--usable", "true");
        Assert.Contains($"cp{t}-ann", usable.Out);
        Assert.DoesNotContain($"cp{t}-off", usable.Out);
        var unusable = await Gk("user", "list", "--prefix", $"cp{t}", "--usable", "false");
        Assert.Contains($"cp{t}-off", unusable.Out);
        Assert.DoesNotContain($"cp{t}-ann", unusable.Out);
    }

    [Fact]
    public async Task A_one_character_prefix_is_refused_with_a_message()
    {
        var r = await Gk("user", "list", "--prefix", "a");
        Assert.NotEqual(0, r.Code);
        Assert.Contains("usernamePrefix", r.Err + r.Out);
        // wildcard characters are sent as data, not interpreted
        var wild = await Gk("user", "list", "--prefix", "%%");
        Assert.Equal(0, wild.Code);
        Assert.DoesNotContain("@", wild.Out);
    }
}
