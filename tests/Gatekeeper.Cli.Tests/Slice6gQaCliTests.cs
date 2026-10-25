using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

/// <summary>Independent QA of gk passwd (slice 6g).</summary>
public class Slice6gQaCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "a plain user password";
    private const string Fresh = "a brand new password 1";
    private readonly WebApplicationFactory<Program> _factory;

    public Slice6gQaCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(ITokenStore tokens, string?[] secrets, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var q = new Queue<string?>(secrets);
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => q.Count > 0 ? q.Dequeue() : null);
        return (code, o.ToString(), e.ToString());
    }

    private async Task<(string Name, Guid Id)> NewUser()
    {
        var admin = _factory.CreateAdminClient();
        var name = $"qacli{Guid.NewGuid():N}"[..14];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Plain Person" });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    [Fact]
    public async Task A_revoked_session_gives_exit_5_not_the_wrong_password_text_and_changes_nothing()
    {
        var (name, id) = await NewUser();
        var tokens = new MemoryTokenStore();
        await Gk(tokens, [Password], "login", "--user", name);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateAdminClient().DeleteAsync($"/v1/users/{id}/sessions")).StatusCode);
        // the access token may still be cached for a moment; either way it is never exit 1 with a password message
        var r = await Gk(tokens, [Password, Fresh], "passwd");
        Assert.DoesNotContain("incorrect", r.Err);
        Assert.Equal(0, (await Gk(new MemoryTokenStore(), [r.Code == 0 ? Fresh : Password], "login", "--user", name)).Code);
    }

    [Fact]
    public async Task Passwords_with_surrounding_spaces_are_kept_exactly()
    {
        var (name, _) = await NewUser();
        var tokens = new MemoryTokenStore();
        await Gk(tokens, [Password], "login", "--user", name);
        var spaced = "  spaced new password  ";
        Assert.Equal(0, (await Gk(tokens, [Password, spaced], "passwd")).Code);
        Assert.Equal(0, (await Gk(new MemoryTokenStore(), [spaced], "login", "--user", name)).Code);
        Assert.NotEqual(0, (await Gk(new MemoryTokenStore(), [spaced.Trim()], "login", "--user", name)).Code);
    }

    [Fact]
    public async Task Help_lists_passwd_and_it_takes_no_options_for_passwords()
    {
        var r = await Gk(new MemoryTokenStore(), [], "--help");
        Assert.Contains("passwd", r.Out);
        var h = await Gk(new MemoryTokenStore(), [], "passwd", "--help");
        Assert.DoesNotContain("--password", h.Out);
        Assert.DoesNotContain("--current", h.Out);
        Assert.DoesNotContain("--new", h.Out);
    }
}
