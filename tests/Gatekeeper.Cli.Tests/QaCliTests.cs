using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class QaCliTests(WebApplicationFactory<Program> f) : IClassFixture<WebApplicationFactory<Program>>
{
    private static string U(string p) => $"{p}-{Guid.NewGuid():N}"[..20];
    private async Task<(int Code, string Out, string Err)> Gk(params string[] a)
    {
        var o = new StringWriter(); var e = new StringWriter();
        return (await CliApp.RunAsync(a, _ => f.CreateClient(), o, e), o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Resolve_by_id_and_by_name_and_case_insensitive_name()
    {
        var app = U("app");
        var c = await Gk("app", "create", app, "--json");
        var id = JsonDocument.Parse(c.Out).RootElement.GetProperty("id").GetString()!;
        Assert.Equal(0, (await Gk("app", "get", id)).Code);
        Assert.Equal(0, (await Gk("app", "get", app.ToUpperInvariant())).Code);
        Assert.Equal(0, (await Gk("role", "create", "admin", "--app", id)).Code);
        Assert.Equal(0, (await Gk("role", "get", "admin", "--app", app)).Code);
        Assert.Equal(2, (await Gk("role", "get", "nope", "--app", app)).Code);
        Assert.Equal(2, (await Gk("role", "get", Guid.NewGuid().ToString())).Code);
        Assert.Equal(2, (await Gk("role", "list", "--app", U("none"))).Code);
    }

    [Fact]
    public async Task Json_output_for_list_delete_and_errors_go_to_stderr()
    {
        var app = U("app");
        await Gk("app", "create", app);
        var l = await Gk("app", "list", "--json");
        Assert.Equal(JsonValueKind.Array, JsonDocument.Parse(l.Out).RootElement.ValueKind);
        var d = await Gk("app", "delete", app, "--json");
        Assert.Equal("deleted", JsonDocument.Parse(d.Out).RootElement.GetProperty("result").GetString());
        var err = await Gk("app", "get", app, "--json");
        Assert.Equal(2, err.Code); Assert.Equal("", err.Out); Assert.NotEqual("", err.Err);
    }

    [Fact]
    public async Task Conflict_on_user_create_role_create_and_rename_exit_3()
    {
        var app = U("app"); var u = U("user");
        await Gk("app", "create", app); await Gk("role", "create", "a", "--app", app); await Gk("role", "create", "b", "--app", app);
        Assert.Equal(3, (await Gk("role", "create", "a", "--app", app)).Code);
        Assert.Equal(3, (await Gk("role", "update", "b", "--app", app, "--name", "a")).Code);
        await Gk("user", "create", u, "--email", $"{u}@example.com");
        Assert.Equal(3, (await Gk("user", "create", u, "--email", $"x{u}@example.com")).Code);
    }

    [Fact]
    public async Task Usage_errors_exit_nonzero_and_url_env_invalid_exit_1()
    {
        Assert.NotEqual(0, (await Gk("app", "create")).Code);
        Assert.NotEqual(0, (await Gk("bogus")).Code);
        Assert.Equal(1, (await Gk("app", "list", "--url", "not a url")).Code);
    }

    [Fact]
    public async Task Update_can_clear_display_name_and_description()
    {
        var u = U("user"); var app = U("app");
        await Gk("user", "create", u, "--email", $"{u}@example.com", "--display-name", "Orig");
        await Gk("user", "update", u, "--display-name", "");
        Assert.Equal("", JsonDocument.Parse((await Gk("user", "get", u, "--json")).Out).RootElement.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task User_roles_with_app_filter_and_inactive_flag()
    {
        var a1 = U("app"); var a2 = U("app"); var u = U("user");
        await Gk("app", "create", a1); await Gk("app", "create", a2);
        await Gk("role", "create", "r1", "--app", a1); await Gk("role", "create", "r2", "--app", a2);
        await Gk("user", "create", u, "--email", $"{u}@example.com", "--inactive");
        await Gk("user", "assign", u, "r1", "--app", a1); await Gk("user", "assign", u, "r2", "--app", a2);
        var r = await Gk("user", "roles", u, "--app", a1, "--json");
        Assert.Equal(1, JsonDocument.Parse(r.Out).RootElement.GetArrayLength());
        var l = await Gk("user", "list", "--active", "false", "--json");
        Assert.Contains(u, l.Out);
        Assert.Equal(2, (await Gk("user", "revoke", u, "r1", "--app", a2)).Code);
        Assert.Equal(0, (await Gk("user", "revoke", u, "r1", "--app", a1)).Code);
        Assert.Equal(2, (await Gk("user", "revoke", u, "r1", "--app", a1)).Code);
    }
}
