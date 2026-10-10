using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class CliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public CliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private static string U(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task<(int Code, string Out, string Err)> Gk(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Full_flow_by_names()
    {
        var app = U("app"); var user = U("user");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        Assert.Equal(0, (await Gk("role", "create", "admin", "--app", app, "--description", "all")).Code);
        Assert.Equal(0, (await Gk("user", "create", user, "--email", $"{user}@example.com")).Code);
        Assert.Equal(0, (await Gk("user", "assign", user, "admin", "--app", app)).Code);

        var roles = await Gk("user", "roles", user);
        Assert.Equal(0, roles.Code);
        Assert.Contains("admin", roles.Out);

        Assert.Equal(0, (await Gk("user", "revoke", user, "admin", "--app", app)).Code);
        Assert.Equal("", (await Gk("user", "roles", user)).Out);

        Assert.Equal(0, (await Gk("role", "delete", "admin", "--app", app)).Code);
        Assert.Equal(0, (await Gk("app", "delete", app)).Code);
        Assert.Equal(2, (await Gk("app", "get", app)).Code);
    }

    [Fact]
    public async Task Duplicate_exits_3_and_unknown_exits_2()
    {
        var app = U("app");
        await Gk("app", "create", app);
        var dup = await Gk("app", "create", app);
        Assert.Equal(3, dup.Code);
        Assert.Contains("already exists", dup.Err);
        Assert.Equal(2, (await Gk("user", "get", U("nobody"))).Code);
    }

    [Fact]
    public async Task Invalid_input_exits_1_with_message()
    {
        var r = await Gk("app", "create", "Bad Name");
        Assert.Equal(1, r.Code);
        Assert.Contains("name", r.Err);
    }

    [Fact]
    public async Task Role_name_without_app_is_an_error()
    {
        var user = U("user");
        await Gk("user", "create", user, "--email", $"{user}@example.com");
        var r = await Gk("user", "assign", user, "admin");
        Assert.Equal(1, r.Code);
        Assert.Contains("--app", r.Err);
    }

    [Fact]
    public async Task Json_flag_prints_valid_json()
    {
        var user = U("user");
        var r = await Gk("user", "create", user, "--email", $"{user}@example.com", "--json");
        Assert.Equal(0, r.Code);
        Assert.Equal(user, JsonDocument.Parse(r.Out).RootElement.GetProperty("username").GetString());
    }

    [Fact]
    public async Task Update_user_changes_only_given_fields()
    {
        var user = U("user");
        await Gk("user", "create", user, "--email", $"{user}@example.com", "--display-name", "Orig");
        Assert.Equal(0, (await Gk("user", "update", user, "--active", "false")).Code);
        var got = await Gk("user", "get", user, "--json");
        var root = JsonDocument.Parse(got.Out).RootElement;
        Assert.False(root.GetProperty("isActive").GetBoolean());
        Assert.Equal("Orig", root.GetProperty("displayName").GetString());
    }

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com")]
    public async Task Non_http_url_exits_1(string url)
    {
        var r = await Gk("app", "list", "--url", url);
        Assert.Equal(1, r.Code);
        Assert.Contains("http", r.Err);
    }

    [Fact]
    public async Task Unreachable_server_exits_4()
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(["app", "list", "--url", "http://127.0.0.1:1"],
            uri => new HttpClient { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(3) }, o, e);
        Assert.Equal(4, code);
    }
}
