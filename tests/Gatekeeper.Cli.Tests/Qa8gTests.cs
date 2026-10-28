using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class Qa8gTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public Qa8gTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(params string[] args)
    {
        TestAuth.AdminToken(_factory);
        var o = new StringWriter(); var e = new StringWriter();
        var tokens = new MemoryTokenStore();
        Assert.Equal(0, await CliApp.RunAsync(["login", "--user", TestAuth.AdminName], _ => _factory.CreateClient(), new StringWriter(), new StringWriter(), tokens, (_, _) => TestAuth.AdminPassword));
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => null);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Bad_usable_value_is_a_usage_error_not_a_request()
    {
        var r = await Gk("user", "list", "--usable", "maybe");
        Assert.NotEqual(0, r.Code);
    }

    [Fact]
    public async Task Flags_combine_with_existing_ones_and_empty_prefix_is_refused()
    {
        var t = Guid.NewGuid().ToString("N")[..8];
        Assert.Equal(0, (await Gk("user", "create", $"qc{t}-a", "--email", $"a+{t}@example.com")).Code);
        var ok = await Gk("user", "list", "--prefix", $"QC{t}", "--email-prefix", $"A+{t}", "--active", "true", "--kind", "person", "--usable", "true");
        Assert.Equal(0, ok.Code);
        Assert.Contains($"qc{t}-a", ok.Out);
        var none = await Gk("user", "list", "--prefix", $"qc{t}", "--active", "false");
        Assert.Equal(0, none.Code);
        Assert.DoesNotContain($"qc{t}-a", none.Out);
        var empty = await Gk("user", "list", "--prefix", "");
        Assert.NotEqual(0, empty.Code);
        var bad = await Gk("user", "list", "--email-prefix", "x");
        Assert.NotEqual(0, bad.Code);
        Assert.Contains("emailPrefix", bad.Err + bad.Out);
    }
}
