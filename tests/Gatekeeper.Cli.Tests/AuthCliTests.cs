using System.Net.Http.Json;
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

    private async Task<(int Code, string Out, string Err)> GkWithPassword(string password, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, _tokens, (_, _) => password);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Audit_list_shows_recent_changes_and_filters()
    {
        var name = $"cli-aud-{Guid.NewGuid():N}"[..20];
        Assert.Equal(0, (await Gk(true, null, "app", "create", name)).Code);
        Assert.Equal(0, (await Gk(true, null, "app", "update", name, "--name", name + "x")).Code);
        var all = await Gk(true, null, "audit", "list", "--limit", "20");
        Assert.Equal(0, all.Code);
        Assert.Contains("POST /v1/applications", all.Out);
        Assert.Contains("PATCH /v1/applications/{id}", all.Out);
        var none = await Gk(true, null, "audit", "list", "--actor", "nobody-at-all");
        Assert.Equal(0, none.Code);
        Assert.Equal("", none.Out.Trim());
        Assert.NotEqual(0, (await Gk(true, null, "audit", "list", "--limit", "0")).Code);
        Assert.Equal(5, (await Gk(false, null, "audit", "list")).Code);
    }

    [Fact]
    public async Task Client_commands_create_rotate_and_assign_roles()
    {
        var app = $"cli-app-{Guid.NewGuid():N}"[..20];
        var client = $"cli-svc-{Guid.NewGuid():N}"[..20];
        Assert.Equal(0, (await Gk(true, null, "app", "create", app)).Code);
        Assert.Equal(0, (await Gk(true, null, "role", "create", "reader", "--app", app)).Code);

        var created = await Gk(true, null, "client", "create", client, "--app", app);
        Assert.Equal(0, created.Code);
        var secret = created.Out.Split('\n').Single(l => l.StartsWith("secret: ")).Substring(8).Trim();
        Assert.StartsWith("gks_", secret);
        Assert.Contains("cannot be shown again", created.Err);

        Assert.Equal(0, (await Gk(true, null, "client", "assign", client, "reader")).Code);
        Assert.Contains("reader", (await Gk(true, null, "client", "roles", client)).Out);
        Assert.Contains(client, (await Gk(true, null, "client", "list", "--app", app)).Out);
        Assert.DoesNotContain("secret", (await Gk(true, null, "client", "get", client)).Out);

        var http = _factory.CreateClient();
        Assert.Equal(System.Net.HttpStatusCode.OK, (await http.PostAsJsonAsync("/v1/auth/client-token", new { clientId = client, clientSecret = secret })).StatusCode);
        var rotated = await Gk(true, null, "client", "rotate-secret", client);
        Assert.Equal(0, rotated.Code);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await http.PostAsJsonAsync("/v1/auth/client-token", new { clientId = client, clientSecret = secret })).StatusCode);

        Assert.Equal(0, (await Gk(true, null, "client", "update", client, "--active", "false")).Code);
        Assert.Contains("isActive: False", (await Gk(true, null, "client", "get", client)).Out);
        Assert.Equal(0, (await Gk(true, null, "client", "revoke", client, "reader")).Code);
        Assert.Equal(0, (await Gk(true, null, "client", "delete", client)).Code);
        Assert.Equal(2, (await Gk(true, null, "client", "get", client)).Code);
        Assert.Equal(5, (await Gk(false, null, "client", "list")).Code);
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
        TestAuth.AdminToken(_factory); // creates the reserved admin app, role and the test administrator
        var name = TestAuth.AdminName;

        var login = await GkWithPassword(TestAuth.AdminPassword, "login", "--user", name);
        Assert.Equal(0, login.Code);
        Assert.Contains("logged in", login.Out);
        Assert.NotNull(_tokens.Current);
        Assert.DoesNotContain(TestAuth.AdminPassword, login.Out + login.Err);

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
        await CliApp.RunAsync(["--url", "http://localhost:9999", "app", "list"],
            _ => new HttpClient(new Capture(r => seen = r.Headers.Authorization?.ToString())) { BaseAddress = new Uri("http://localhost:9999") }, o, e, _tokens);
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

public class CliSafetyTests
{
    [Fact]
    public void Safe_text_replaces_escape_sequences_and_bidi_controls()
    {
        Assert.Equal("ok\uFFFD[31mred", Safe.Text("ok\u001b[31mred"));
        Assert.Equal("a\uFFFDb\uFFFDc", Safe.Text("a\u202Eb\u0007c"));
        Assert.Equal("plain \u00e5\u00e4\u00f6 \U0001F600", Safe.Text("plain \u00e5\u00e4\u00f6 \U0001F600"));
        Assert.Equal("", Safe.Text(null));
    }

    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) => Task.FromResult(respond(r));
    }

    private static async Task<(int Code, string Err)> Run(Func<HttpRequestMessage, HttpResponseMessage> respond, params string[] args)
    {
        var e = new StringWriter();
        var code = await CliApp.RunAsync(args, u => new HttpClient(new Stub(respond)) { BaseAddress = u }, new StringWriter(), e, new MemoryTokenStore(), (_, _) => "a long enough password");
        return (code, e.ToString());
    }

    [Fact]
    public async Task Redirects_are_an_error_and_are_not_followed()
    {
        var r = await Run(_ => new HttpResponseMessage(System.Net.HttpStatusCode.TemporaryRedirect), "login", "--user", "alice");
        Assert.Equal(1, r.Code);
        Assert.Contains("redirect", r.Err);
    }

    [Fact]
    public async Task Plain_http_to_a_non_local_host_is_refused()
    {
        var called = false;
        var r = await Run(_ => { called = true; return new HttpResponseMessage(System.Net.HttpStatusCode.OK); }, "--url", "http://gatekeeper.example", "login", "--user", "alice");
        Assert.Equal(1, r.Code);
        Assert.False(called);
        Assert.Contains("https", r.Err);
    }

    [Fact]
    public async Task Server_text_in_error_messages_is_sanitised()
    {
        var r = await Run(_ => new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest)
            { Content = new StringContent("{\"detail\":\"bad\\u001b[2Jthing\"}") }, "app", "create", "x");
        Assert.DoesNotContain('\u001b', r.Err);
    }
}
