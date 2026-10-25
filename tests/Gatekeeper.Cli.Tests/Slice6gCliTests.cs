using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

/// <summary>Slice 6g: gk passwd.</summary>
public class Slice6gCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "a plain user password";
    private const string Fresh = "a brand new password 1";
    private readonly WebApplicationFactory<Program> _factory;

    public Slice6gCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private static async Task<(int Code, string Out, string Err, List<(string Prompt, bool Confirm)> Prompts)> Gk(WebApplicationFactory<Program> f, ITokenStore tokens, string?[] secrets, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var queue = new Queue<string?>(secrets);
        var prompts = new List<(string, bool)>();
        var code = await CliApp.RunAsync(args, _ => f.CreateClient(), o, e, tokens, (p, c) => { prompts.Add((p, c)); return queue.Count > 0 ? queue.Dequeue() : null; });
        return (code, o.ToString(), e.ToString(), prompts);
    }

    private static async Task<string> NewPlainUser(WebApplicationFactory<Program> f)
    {
        var admin = f.CreateAdminClient();
        var name = $"plain{Guid.NewGuid():N}"[..14];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Plain Person" });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return name;
    }

    [Fact]
    public async Task Passwd_prompts_for_both_passwords_changes_it_ends_other_sessions_and_keeps_this_one()
    {
        var name = await NewPlainUser(_factory);
        var mine = new MemoryTokenStore();
        var other = new MemoryTokenStore();
        await Gk(_factory, mine, [Password], "login", "--user", name);
        await Gk(_factory, other, [Password], "login", "--user", name);

        var r = await Gk(_factory, mine, [Password, Fresh], "passwd");
        Assert.Equal(0, r.Code);
        Assert.Contains("password changed", r.Out);
        Assert.Equal([("Current password: ", false), ("New password: ", true)], r.Prompts); // the new one is asked twice by the reader
        Assert.DoesNotContain(Password, r.Out + r.Err);
        Assert.DoesNotContain(Fresh, r.Out + r.Err);

        Assert.Equal(0, (await Gk(_factory, mine, [], "me")).Code);
        Assert.Equal(5, (await Gk(_factory, other, [], "me")).Code); // its session is over
        Assert.Equal(5, (await Gk(_factory, new MemoryTokenStore(), [Password], "login", "--user", name)).Code); // old password
        Assert.Equal(0, (await Gk(_factory, new MemoryTokenStore(), [Fresh], "login", "--user", name)).Code);
    }

    [Fact]
    public async Task A_wrong_current_password_is_exit_1_with_a_fixed_text_and_the_session_stays()
    {
        var name = await NewPlainUser(_factory);
        var tokens = new MemoryTokenStore();
        await Gk(_factory, tokens, [Password], "login", "--user", name);
        var r = await Gk(_factory, tokens, ["WRONG-secret-current", Fresh], "passwd");
        Assert.Equal(1, r.Code); // not 5: the login is fine
        Assert.Contains("The current password is incorrect.", r.Err);
        Assert.DoesNotContain("not allowed", r.Err);
        Assert.DoesNotContain("WRONG-secret-current", r.Out + r.Err);
        Assert.DoesNotContain(Fresh, r.Out + r.Err);
        Assert.Equal(0, (await Gk(_factory, tokens, [], "me")).Code);
        Assert.NotNull(tokens.Current); // the saved login was not cleared
    }

    [Fact]
    public async Task Same_password_missing_input_and_no_login_are_refused()
    {
        var name = await NewPlainUser(_factory);
        var tokens = new MemoryTokenStore();
        await Gk(_factory, tokens, [Password], "login", "--user", name);
        var same = await Gk(_factory, tokens, [Password, Password], "passwd");
        Assert.Equal(1, same.Code);
        Assert.Contains("must differ", same.Err);
        Assert.Equal(1, (await Gk(_factory, tokens, [], "passwd")).Code); // end of input
        Assert.Equal(1, (await Gk(_factory, tokens, [Password], "passwd")).Code);
        Assert.Equal(1, (await Gk(_factory, tokens, [Password, "short"], "passwd")).Code); // the rules come from the API
        Assert.Equal(5, (await Gk(_factory, new MemoryTokenStore(), [Password, Fresh], "passwd")).Code);
        Assert.Equal(0, (await Gk(_factory, new MemoryTokenStore(), [Password], "login", "--user", name)).Code); // unchanged
    }

    [Fact]
    public async Task The_password_cannot_be_given_as_an_argument()
    {
        var name = await NewPlainUser(_factory);
        var tokens = new MemoryTokenStore();
        await Gk(_factory, tokens, [Password], "login", "--user", name);
        var r = await Gk(_factory, tokens, [Password, Fresh], "passwd", "--password", "x");
        Assert.NotEqual(0, r.Code);
        Assert.Equal(0, (await Gk(_factory, new MemoryTokenStore(), [Password], "login", "--user", name)).Code);
    }

    [Fact]
    public async Task Throttled_attempts_are_exit_1_with_the_servers_text()
    {
        using var f = new WebApplicationFactory<Program>();
        var name = await NewPlainUser(f);
        var tokens = new MemoryTokenStore();
        await Gk(f, tokens, [Password], "login", "--user", name);
        for (var i = 0; i < 5; i++) Assert.Equal(1, (await Gk(f, tokens, [$"wrong password {i} here", Fresh], "passwd")).Code);
        var r = await Gk(f, tokens, [Password, Fresh], "passwd");
        Assert.Equal(1, r.Code);
        Assert.Contains("Too many failed attempts", r.Err);
        Assert.Equal(0, (await Gk(f, new MemoryTokenStore(), [Password], "login", "--user", name)).Code); // not applied
    }
}
