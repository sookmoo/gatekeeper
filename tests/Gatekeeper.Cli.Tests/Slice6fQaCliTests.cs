using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class Slice6fQaCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "a plain user password";
    private readonly WebApplicationFactory<Program> _factory;
    public Slice6fQaCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(ITokenStore tokens, string? secret, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => secret);
        return (code, o.ToString(), e.ToString());
    }

    private async Task<string> NewUser(string? kind)
    {
        var admin = _factory.CreateAdminClient();
        var name = $"qa{Guid.NewGuid():N}"[..14];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Q A", kind });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return name;
    }

    [Fact]
    public async Task A_shared_account_cannot_log_in_through_the_cli_and_nothing_is_stored()
    {
        var name = await NewUser("shared");
        var tokens = new MemoryTokenStore();
        var r = await Gk(tokens, Password, "login", "--user", name);
        Assert.NotEqual(0, r.Code);
        Assert.Null(tokens.Current);
        Assert.Equal(5, (await Gk(tokens, null, "me")).Code);
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_give_the_same_cli_result()
    {
        var name = await NewUser(null);
        var a = await Gk(new MemoryTokenStore(), "wrong password here", "login", "--user", name);
        var b = await Gk(new MemoryTokenStore(), "wrong password here", "login", "--user", "nobody" + Guid.NewGuid().ToString("N")[..6]);
        Assert.Equal(a.Code, b.Code);
        Assert.Equal(a.Err, b.Err);
    }

    [Fact]
    public async Task Me_output_has_no_token_or_hash_and_sessions_hide_secrets()
    {
        var name = await NewUser(null);
        var tokens = new MemoryTokenStore();
        await Gk(tokens, Password, "login", "--user", name);
        var all = (await Gk(tokens, null, "me")).Out + (await Gk(tokens, null, "me", "sessions")).Out;
        Assert.DoesNotContain(tokens.Current!.RefreshToken!, all);
        Assert.DoesNotContain("hash", all, StringComparison.OrdinalIgnoreCase);
    }
}
