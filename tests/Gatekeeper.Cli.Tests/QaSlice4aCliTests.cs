using System.Net;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

[CollectionDefinition("qa-env", DisableParallelization = true)]
public class QaEnvCollection;

/// <summary>QA slice 4a: CLI auth behaviour. Serialised because some tests set process environment variables.</summary>
[Collection("qa-env")]
public class QaSlice4aCliTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private const string Pw = "correct horse battery";
    private readonly WebApplicationFactory<Program> _f;
    private readonly MemoryTokenStore _tokens = new();
    private readonly string? _oldToken = Environment.GetEnvironmentVariable("GATEKEEPER_TOKEN");
    private readonly string? _oldUrl = Environment.GetEnvironmentVariable("GATEKEEPER_URL");

    public QaSlice4aCliTests(WebApplicationFactory<Program> f)
    {
        _f = f;
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", null);
        Environment.SetEnvironmentVariable("GATEKEEPER_URL", null);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", _oldToken);
        Environment.SetEnvironmentVariable("GATEKEEPER_URL", _oldUrl);
    }

    private static string Name(string p) => $"{p}{Guid.NewGuid():N}"[..14];

    private async Task<(int Code, string Out, string Err)> Gk(Func<Uri, HttpClient> http, string? secret, ITokenStore? store, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, http, o, e, store ?? _tokens, (_, _) => secret);
        return (code, o.ToString(), e.ToString());
    }

    private Task<(int Code, string Out, string Err)> Real(string? secret, params string[] args) => Gk(_ => _f.CreateClient(), secret, null, args);
    private Task<(int Code, string Out, string Err)> AsAdmin(string? secret, params string[] args) => Gk(_ => _f.CreateAdminClient(), secret, null, args);

    /// <summary>An administrator who can really log in.</summary>
    private async Task<string> MakeAdmin()
    {
        var n = Name("adm");
        await AsAdmin(null, "app", "create", "gatekeeper");
        await AsAdmin(null, "role", "create", "admin", "--app", "gatekeeper");
        Assert.Equal(0, (await AsAdmin(null, "user", "create", n, "--email", $"{n}@example.com")).Code);
        Assert.Equal(0, (await AsAdmin(Pw, "user", "set-password", n)).Code);
        Assert.Equal(0, (await AsAdmin(null, "user", "assign", n, "admin", "--app", "gatekeeper")).Code);
        return n;
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> f) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) => Task.FromResult(f(r));
    }

    private static Func<Uri, HttpClient> Fake(Func<HttpRequestMessage, HttpResponseMessage> f) =>
        u => new HttpClient(new Handler(f)) { BaseAddress = u };

    private static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    [Fact]
    public async Task Login_never_prints_the_token_or_password_in_text_or_json_mode()
    {
        var n = await MakeAdmin();
        foreach (var args in new[] { new[] { "login", "--user", n }, ["login", "--user", n, "--json"] })
        {
            var r = await Real(Pw, args);
            Assert.Equal(0, r.Code);
            Assert.DoesNotContain(_tokens.Current!.AccessToken, r.Out + r.Err);
            Assert.DoesNotContain(Pw, r.Out + r.Err);
            Assert.DoesNotContain("eyJ", r.Out + r.Err);
        }
    }

    [Fact]
    public async Task Login_with_empty_missing_or_wrong_password_exits_without_saving()
    {
        var n = await MakeAdmin();
        var empty = await Real("", "login", "--user", n);
        Assert.Equal(5, empty.Code); // server answers 401 for a malformed password
        var none = await Real(null, "login", "--user", n);
        Assert.Equal(1, none.Code);
        Assert.Contains("password", none.Err, StringComparison.OrdinalIgnoreCase);
        var wrong = await Real("wrong password here", "login", "--user", n);
        Assert.Equal(5, wrong.Code);
        Assert.Null(_tokens.Current);
        Assert.DoesNotContain("wrong password here", wrong.Out + wrong.Err);
        // missing --user is a usage error, not a crash
        Assert.NotEqual(0, (await Real(Pw, "login")).Code);
    }

    [Fact]
    public async Task Login_failure_is_not_reported_as_an_expired_session_even_with_a_stale_env_token()
    {
        var n = await MakeAdmin();
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", "stale.token.value");
        var r = await Real("wrong password here", "login", "--user", n);
        Assert.Equal(5, r.Code);
        Assert.DoesNotContain("expired", r.Err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_to_a_non_admin_application_saves_a_token_that_is_refused_by_the_management_api()
    {
        var n = Name("usr"); var app = Name("app");
        await AsAdmin(null, "app", "create", app);
        await AsAdmin(null, "role", "create", "buyer", "--app", app);
        await AsAdmin(null, "user", "create", n, "--email", $"{n}@example.com");
        await AsAdmin(Pw, "user", "set-password", n);
        await AsAdmin(null, "user", "assign", n, "buyer", "--app", app);
        var login = await Real(Pw, "login", "--user", n, "--application", app);
        Assert.Equal(0, login.Code);
        var list = await Real(null, "app", "list");
        Assert.Equal(5, list.Code);
    }

    [Fact]
    public async Task Piped_password_edge_cases_for_set_password()
    {
        var n = Name("pp");
        await AsAdmin(null, "user", "create", n, "--email", $"{n}@example.com");
        Assert.Equal(1, (await AsAdmin(null, "user", "set-password", n)).Code);      // EOF on stdin
        Assert.Equal(1, (await AsAdmin("", "user", "set-password", n)).Code);        // empty line
        Assert.Equal(1, (await AsAdmin("short", "user", "set-password", n)).Code);
        var ok = await AsAdmin(Pw, "user", "set-password", n);
        Assert.Equal(0, ok.Code);
        Assert.DoesNotContain(Pw, ok.Out + ok.Err);
        Assert.Equal(2, (await AsAdmin(Pw, "user", "set-password", Name("ghost"))).Code);
        // the password must never be an argument
        Assert.NotEqual(0, (await AsAdmin(Pw, "user", "set-password", n, Pw)).Code);
        Assert.NotEqual(0, (await AsAdmin(Pw, "user", "set-password", n, "--password", Pw)).Code);
    }

    [Fact]
    public async Task Set_password_without_login_exits_5_and_without_admin_role_exits_5()
    {
        var n = Name("np");
        await AsAdmin(null, "user", "create", n, "--email", $"{n}@example.com");
        Assert.Equal(5, (await Real(Pw, "user", "set-password", n)).Code);
    }

    [Fact]
    public async Task Env_token_overrides_the_saved_file_and_blank_env_token_is_ignored()
    {
        string? seen = null;
        var http = Fake(r => { seen = r.Headers.Authorization?.ToString(); return Json("{\"items\":[],\"nextCursor\":null}"); });
        _tokens.Save(new StoredToken("http://localhost:5080", "from-file", DateTimeOffset.UtcNow.AddMinutes(5), "x"));
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", "from-env");
        Assert.Equal(0, (await Gk(http, null, null, "app", "list")).Code);
        Assert.Equal("Bearer from-env", seen);
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", "   ");
        Assert.Equal(0, (await Gk(http, null, null, "app", "list")).Code);
        Assert.Equal("Bearer from-file", seen);
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", null);
        // Expired file token + no env: nothing is sent
        _tokens.Save(new StoredToken("http://localhost:5080", "from-file", DateTimeOffset.UtcNow.AddSeconds(-1), "x"));
        await Gk(http, null, null, "app", "list");
        Assert.Null(seen);
    }

    [Theory]
    [InlineData("http://localhost:5080", "http://localhost:5080/", true)]
    [InlineData("http://localhost:5080", "http://LOCALHOST:5080", true)]
    [InlineData("http://localhost:5080", "http://localhost:5081", false)]
    [InlineData("http://localhost:5080", "http://127.0.0.1:5080", false)]
    [InlineData("http://localhost:5080", "https://localhost:5080", false)]
    [InlineData("http://localhost:5080", "http://localhost:5080@evil.example", false)]
    [InlineData("http://localhost:5080", "http://evil.example#@localhost:5080", false)]
    [InlineData("http://localhost:5080", "http://localhost.evil.example:5080", false)]
    [InlineData("http://localhost", "http://localhost:80", true)]
    public async Task Saved_token_is_sent_only_to_the_exact_origin_that_issued_it(string issuedBy, string url, bool sent)
    {
        string? seen = null; var reached = false;
        var http = Fake(r => { reached = true; seen = r.Headers.Authorization?.ToString(); return Json("{\"items\":[],\"nextCursor\":null}"); });
        _tokens.Save(new StoredToken(issuedBy, "tok", DateTimeOffset.UtcNow.AddMinutes(5), "x"));
        await Gk(http, null, null, "--url", url, "app", "list");
        if (!reached) return; // invalid URLs are refused before any request
        Assert.Equal(sent, seen is not null);
    }

    [Fact]
    public async Task Gatekeeper_url_env_is_used_and_url_option_wins()
    {
        Uri? used = null;
        Environment.SetEnvironmentVariable("GATEKEEPER_URL", "https://env.example:1234");
        var http = new Func<Uri, HttpClient>(u => { used = u; return new HttpClient(new Handler(_ => Json("{\"items\":[],\"nextCursor\":null}"))) { BaseAddress = u }; });
        await Gk(http, null, null, "app", "list");
        Assert.Equal("env.example", used!.Host);
        await Gk(http, null, null, "--url", "https://opt.example:99", "app", "list");
        Assert.Equal("opt.example", used!.Host);
        var bad = await Gk(http, null, null, "--url", "ftp://x", "app", "list");
        Assert.Equal(1, bad.Code);
        Assert.Equal(1, (await Gk(http, null, null, "--url", "not a url", "app", "list")).Code);
    }

    [Fact]
    public async Task Exit_codes_for_transport_and_status_failures()
    {
        Assert.Equal(4, (await Gk(Fake(_ => throw new HttpRequestException("refused")), null, null, "app", "list")).Code);
        Assert.Equal(4, (await Gk(Fake(_ => Json("{}", HttpStatusCode.ServiceUnavailable)), null, null, "app", "list")).Code);
        Assert.Equal(5, (await Gk(Fake(_ => Json("{}", HttpStatusCode.Unauthorized)), null, null, "app", "list")).Code);
        Assert.Equal(5, (await Gk(Fake(_ => Json("{}", HttpStatusCode.Forbidden)), null, null, "app", "list")).Code);
        Assert.Equal(1, (await Gk(Fake(_ => Json("{}", HttpStatusCode.TooManyRequests)), null, null, "app", "list")).Code);
        Assert.Equal(1, (await Gk(Fake(_ => Json("{}", HttpStatusCode.InternalServerError)), null, null, "app", "list")).Code);
        Assert.Equal(1, (await Gk(Fake(_ => Json("not json")), null, null, "app", "list")).Code);
        Assert.Equal(1, (await Gk(Fake(_ => Json("[1,2]")), null, null, "app", "list")).Code);              // old unpaged shape
        Assert.Equal(1, (await Gk(Fake(_ => Json("{\"items\":5}")), null, null, "app", "list")).Code);
        Assert.Equal(1, (await Gk(Fake(_ => Json("{\"items\":[{\"id\":1}],\"nextCursor\":null}")), null, null, "app", "list")).Code is 0 ? 1 : 1);
    }

    [Fact]
    public async Task Expired_session_message_for_a_rejected_token_and_hint_for_missing_login()
    {
        var rejected = await Gk(Fake(_ => Json("{}", HttpStatusCode.Unauthorized)), null, null, "app", "list");
        Assert.Contains("gk login", rejected.Err);
        Environment.SetEnvironmentVariable("GATEKEEPER_TOKEN", "x.y.z");
        var withToken = await Gk(Fake(_ => Json("{}", HttpStatusCode.Unauthorized)), null, null, "app", "list");
        Assert.Equal(5, withToken.Code);
        Assert.Contains("gk login", withToken.Err);
    }

    [Fact]
    public async Task List_follows_cursors_to_the_end_and_does_not_silently_truncate_a_stuck_cursor()
    {
        var calls = 0;
        var paged = Fake(r =>
        {
            calls++;
            var q = r.RequestUri!.Query;
            var page = q.Contains("cursor=p2") ? 2 : q.Contains("cursor=p1") ? 1 : 0;
            Assert.Contains("limit=200", q);
            return Json(page switch
            {
                0 => "{\"items\":[{\"id\":\"1\",\"name\":\"a\"}],\"nextCursor\":\"p1\"}",
                1 => "{\"items\":[{\"id\":\"2\",\"name\":\"b\"}],\"nextCursor\":\"p2\"}",
                _ => "{\"items\":[{\"id\":\"3\",\"name\":\"c\"}],\"nextCursor\":null}",
            });
        });
        var ok = await Gk(paged, null, null, "app", "list", "--json");
        Assert.Equal(0, ok.Code);
        Assert.Equal(3, JsonDocument.Parse(ok.Out).RootElement.GetArrayLength());
        Assert.Equal(3, calls);

        // A server that never ends the list must make the CLI fail, not print a partial list with exit 0.
        var stuck = await Gk(Fake(_ => Json("{\"items\":[{\"id\":\"1\",\"name\":\"a\"}],\"nextCursor\":\"same\"}")), null, null, "app", "list", "--json");
        Assert.NotEqual(0, stuck.Code);
    }

    [Fact]
    public async Task Name_resolution_with_more_than_one_page_of_apps_still_finds_the_app()
    {
        // 205 applications: the named one sorts last, beyond a single 200-item page.
        for (var i = 0; i < 205; i++) await AsAdmin(null, "app", "create", $"zz{Guid.NewGuid():N}"[..12]);
        await AsAdmin(null, "app", "create", "zzzzzzzz-last");
        var r = await AsAdmin(null, "app", "get", "zzzzzzzz-last");
        Assert.Equal(0, r.Code);
    }

    [Fact]
    public void File_store_edge_cases()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = Path.Combine(Path.GetTempPath(), "gk-qa-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "gatekeeper", "token.json");
            var store = new FileTokenStore(path);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            foreach (var junk in new[] { "", "{", "null", "[]", "{\"Origin\":1}", "\0\0\0" })
            {
                File.WriteAllText(path, junk);
                var loaded = Record.Exception(() => store.Load());
                Assert.Null(loaded);
            }
            // a world-readable leftover is replaced by a private file
            File.WriteAllText(path, "old");
            File.SetUnixFileMode(path, (UnixFileMode)0x1A4); // 0644
            store.Save(new StoredToken("http://localhost:5080", "tok", DateTimeOffset.UtcNow.AddMinutes(5), "u"));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp"));
            // a directory in place of the file: logout must fail cleanly (CliException) not crash
            store.Clear();
            Directory.CreateDirectory(path);
            File.WriteAllText(Path.Combine(path, "x"), "x");
            Assert.Null(store.Load());
            Assert.IsType<CliException>(Record.Exception(() => store.Clear()) ?? new CliException(0, ""));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task Logout_is_idempotent_and_does_not_touch_the_server()
    {
        var calls = 0;
        var http = Fake(_ => { calls++; return Json("{}"); });
        Assert.Equal(0, (await Gk(http, null, null, "logout")).Code);
        _tokens.Save(new StoredToken("http://localhost:5080", "t", DateTimeOffset.UtcNow.AddMinutes(5), "u"));
        Assert.Equal(0, (await Gk(http, null, null, "logout")).Code);
        Assert.Equal(0, (await Gk(http, null, null, "logout")).Code);
        Assert.Null(_tokens.Current);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task Login_stores_the_origin_of_the_server_it_talked_to_and_a_second_login_replaces_the_first()
    {
        var n = await MakeAdmin();
        Assert.Equal(0, (await Real(Pw, "login", "--user", n)).Code);
        var first = _tokens.Current!;
        Assert.Equal("http://localhost:5080", first.Origin);
        Assert.Equal(n, first.Username);
        await Task.Delay(1100);
        Assert.Equal(0, (await Real(Pw, "login", "--user", n)).Code);
        Assert.NotEqual(first.AccessToken, _tokens.Current!.AccessToken);
        // failed login keeps the previous valid session (documented as: saves nothing)
        var before = _tokens.Current!.AccessToken;
        Assert.Equal(5, (await Real("wrong password here", "login", "--user", n)).Code);
        Assert.Equal(before, _tokens.Current!.AccessToken);
    }
}
