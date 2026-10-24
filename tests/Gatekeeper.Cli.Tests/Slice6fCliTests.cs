using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

/// <summary>Slice 6f: gk me, gk me sessions, gk me revoke-session for a user without any role.</summary>
public class Slice6fCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "a plain user password";
    private readonly WebApplicationFactory<Program> _factory;

    public Slice6fCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(ITokenStore tokens, string? secret, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => secret);
        return (code, o.ToString(), e.ToString());
    }

    private async Task<string> NewPlainUser()
    {
        var admin = _factory.CreateAdminClient();
        var name = $"plain{Guid.NewGuid():N}"[..14];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Plain Person" });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return name;
    }

    [Fact]
    public async Task A_user_without_roles_logs_in_and_sees_only_their_own_account_and_sessions()
    {
        var name = await NewPlainUser();
        var tokens = new MemoryTokenStore();
        Assert.Equal(0, (await Gk(tokens, Password, "login", "--user", name)).Code);

        var me = await Gk(tokens, null, "me");
        Assert.Equal(0, me.Code);
        Assert.Contains($"username: {name}", me.Out);
        Assert.Contains("displayName: Plain Person", me.Out);
        Assert.Contains("kind: person", me.Out);

        var sessions = await Gk(tokens, null, "me", "sessions");
        Assert.Equal(0, sessions.Code);
        Assert.Single(sessions.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("gatekeeper", sessions.Out);
        Assert.Contains("True", sessions.Out);

        var admin = await Gk(tokens, null, "app", "list");
        Assert.Equal(5, admin.Code); // refused: not an administrator
    }

    [Fact]
    public async Task Revoke_session_ends_the_own_session_and_a_foreign_or_unknown_id_is_not_found()
    {
        var name = await NewPlainUser();
        var other = await NewPlainUser();
        var mine = new MemoryTokenStore();
        var theirs = new MemoryTokenStore();
        await Gk(mine, Password, "login", "--user", name);
        await Gk(theirs, Password, "login", "--user", other);
        var foreign = (await Gk(theirs, null, "me", "sessions")).Out.Split(' ')[0].Trim();
        var own = (await Gk(mine, null, "me", "sessions")).Out.Split(' ')[0].Trim();

        Assert.Equal(2, (await Gk(mine, null, "me", "revoke-session", foreign)).Code);
        Assert.Equal(2, (await Gk(mine, null, "me", "revoke-session", Guid.NewGuid().ToString())).Code);
        Assert.Equal(1, (await Gk(mine, null, "me", "revoke-session", "not-a-guid")).Code);
        Assert.Equal(0, (await Gk(theirs, null, "me")).Code);

        var done = await Gk(mine, null, "me", "revoke-session", own);
        Assert.Equal(0, done.Code);
        Assert.Contains("revoked", done.Out);
        var refresh = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = mine.Current!.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task Me_without_a_login_is_exit_5()
    {
        Assert.Equal(5, (await Gk(new MemoryTokenStore(), null, "me")).Code);
    }

    [Fact]
    public async Task Revoke_sessions_ends_the_other_sessions_and_keeps_the_one_in_use()
    {
        var name = await NewPlainUser();
        var mine = new MemoryTokenStore();
        var other = new MemoryTokenStore();
        await Gk(mine, Password, "login", "--user", name);
        await Gk(other, Password, "login", "--user", name);
        var done = await Gk(mine, null, "me", "revoke-sessions");
        Assert.Equal(0, done.Code);
        Assert.Contains("revoked 1 other session(s)", done.Out);
        Assert.Equal(0, (await Gk(mine, null, "me")).Code);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = other.Current!.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = mine.Current!.RefreshToken })).StatusCode);
        Assert.Contains("revoked 0 other session(s)", (await Gk(mine, null, "me", "revoke-sessions")).Out);
        Assert.Equal(5, (await Gk(new MemoryTokenStore(), null, "me", "revoke-sessions")).Code);
    }
}
