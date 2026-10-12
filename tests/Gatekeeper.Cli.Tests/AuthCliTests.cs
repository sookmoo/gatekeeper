using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class AuthCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly MemoryTokenStore _tokens = new();

    public AuthCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(bool admin, string? secret, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => admin ? _factory.CreateAdminClient() : _factory.CreateClient(), o, e,
            _tokens, (_, _) => secret);
        return (code, o.ToString(), e.ToString());
    }

    // Uses the real login flow: the CLI's own ApiClient adds the Authorization header from the saved token.
    private async Task<(int Code, string Out, string Err)> GkAsLoggedIn(params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, _tokens, (_, _) => Password);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Without_a_login_commands_exit_5()
    {
        var r = await GkAsLoggedIn("app", "list");
        Assert.Equal(5, r.Code);
        Assert.Contains("gk login", r.Err);
    }

    [Fact]
    public async Task Login_saves_a_token_that_is_then_used_and_logout_removes_it()
    {
        var name = $"adm{Guid.NewGuid():N}"[..12];
        // Seed the admin app, role and user with the minted admin client.
        Assert.Equal(0, (await Gk(true, null, "app", "create", "gatekeeper")).Code is 0 or 3 ? 0 : 1);
        await Gk(true, null, "role", "create", "admin", "--app", "gatekeeper");
        Assert.Equal(0, (await Gk(true, null, "user", "create", name, "--email", $"{name}@example.com")).Code);
        Assert.Equal(0, (await Gk(true, Password, "user", "set-password", name)).Code);
        Assert.Equal(0, (await Gk(true, null, "user", "assign", name, "admin", "--app", "gatekeeper")).Code);

        var login = await GkAsLoggedIn("login", "--user", name);
        Assert.Equal(0, login.Code);
        Assert.Contains("logged in", login.Out);
        Assert.NotNull(_tokens.Current);
        Assert.DoesNotContain(Password, login.Out + login.Err);

        Assert.Equal(0, (await GkAsLoggedIn("app", "list")).Code);

        Assert.Equal(0, (await GkAsLoggedIn("logout")).Code);
        Assert.Null(_tokens.Current);
        Assert.Equal(5, (await GkAsLoggedIn("app", "list")).Code);
    }

    [Fact]
    public async Task Wrong_password_exits_5_and_saves_nothing()
    {
        var r = await Gk(false, "wrong password here", "login", "--user", "nobody");
        Assert.Equal(5, r.Code);
        Assert.Null(_tokens.Current);
    }

    [Fact]
    public async Task Saved_token_is_not_sent_to_a_different_server()
    {
        _tokens.Save(new StoredToken("http://localhost:5080", AdminToken(), DateTimeOffset.UtcNow.AddMinutes(5), "x"));
        string? seen = null;
        var o = new StringWriter(); var e = new StringWriter();
        await CliApp.RunAsync(["--url", "http://evil.example:9999", "app", "list"],
            _ => new HttpClient(new Capture(r => seen = r.Headers.Authorization?.ToString())) { BaseAddress = new Uri("http://evil.example:9999") }, o, e, _tokens);
        Assert.Null(seen);

        await CliApp.RunAsync(["--url", "http://localhost:5080", "app", "list"],
            _ => new HttpClient(new Capture(r => seen = r.Headers.Authorization?.ToString())) { BaseAddress = new Uri("http://localhost:5080") }, o, e, _tokens);
        Assert.StartsWith("Bearer ", seen);
    }

    [Fact]
    public async Task Expired_saved_token_is_not_sent()
    {
        _tokens.Save(new StoredToken("http://localhost:5080", "stale", DateTimeOffset.UtcNow.AddMinutes(-1), "x"));
        string? seen = "unset";
        await CliApp.RunAsync(["app", "list"],
            _ => new HttpClient(new Capture(r => seen = r.Headers.Authorization?.ToString())) { BaseAddress = new Uri("http://localhost:5080") },
            new StringWriter(), new StringWriter(), _tokens);
        Assert.Null(seen);
    }

    [Fact]
    public void File_store_is_private()
    {
        var dir = Path.Combine(Path.GetTempPath(), "gk-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileTokenStore(Path.Combine(dir, "gatekeeper", "token.json"));
            Assert.Null(store.Load());
            store.Save(new StoredToken("http://localhost:5080", "tok", DateTimeOffset.UtcNow.AddMinutes(5), "alice"));
            Assert.Equal("tok", store.Load()!.AccessToken);
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(dir, "gatekeeper", "token.json")));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.Combine(dir, "gatekeeper")));
            }
            store.Clear();
            Assert.Null(store.Load());
            store.Clear(); // idempotent
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    private string AdminToken() => TestAuth.AdminToken(_factory);

    private sealed class Capture(Action<HttpRequestMessage> seen) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            seen(request);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized));
        }
    }
}
