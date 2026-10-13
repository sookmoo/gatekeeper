using System.Net;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace Gatekeeper.Cli.Tests;

public class Qa4cCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly ITestOutputHelper _out;
    public Qa4cCliTests(WebApplicationFactory<Program> f, ITestOutputHelper o) { _factory = f; _out = o; }

    private sealed class Down : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) => throw new HttpRequestException("connection refused");
    }

    private static async Task<(int Code, string Out, string Err)> Run(Func<Uri, HttpClient> http, ITokenStore tokens, string? secret, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, http, o, e, tokens, (_, _) => secret);
        return (code, o.ToString(), e.ToString());
    }

    private async Task<MemoryTokenStore> LoggedIn()
    {
        TestAuth.AdminToken(_factory);
        var t = new MemoryTokenStore();
        Assert.Equal(0, (await Run(_ => _factory.CreateClient(), t, TestAuth.AdminPassword, "login", "--user", TestAuth.AdminName)).Code);
        return t;
    }

    [Fact]
    public async Task Logout_clears_the_local_login_even_when_the_server_is_unreachable_and_the_access_token_expired()
    {
        var t = await LoggedIn();
        t.Save(t.Current! with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) });
        var r = await Run(_ => new HttpClient(new Down()) { BaseAddress = new Uri("http://localhost:5080") }, t, null, "logout");
        _out.WriteLine($"exit={r.Code} err={r.Err.Trim()} tokenKept={t.Current is not null}");
        Assert.Equal(0, r.Code);
        Assert.Null(t.Current);
    }

    [Fact]
    public async Task Logout_does_not_rotate_the_refresh_token_just_to_end_the_session()
    {
        var t = await LoggedIn();
        t.Save(t.Current! with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) });
        var before = t.Current!.RefreshToken;
        var calls = new List<string>();
        var r = await Run(_ => new HttpClient(new Spy(_factory.Server.CreateHandler(), calls)) { BaseAddress = _factory.Server.BaseAddress }, t, null, "logout");
        _out.WriteLine(string.Join(" ", calls));
        Assert.Equal(0, r.Code);
        Assert.DoesNotContain("/v1/auth/refresh", calls);
    }

    private sealed class Spy(HttpMessageHandler inner, List<string> calls) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) { calls.Add(r.RequestUri!.AbsolutePath); return base.SendAsync(r, ct); }
    }

    [Theory]
    [InlineData("")] [InlineData("null")] [InlineData("{}")] [InlineData("[]")] [InlineData("\"x\"")] [InlineData("{\"Origin\":5}")]
    [InlineData("{\"Origin\":\"http://localhost:5080\",\"AccessToken\":null,\"ExpiresAt\":\"2000-01-01T00:00:00+00:00\",\"Username\":null,\"RefreshToken\":\"gkr_x\",\"RefreshExpiresAt\":\"2999-01-01T00:00:00+00:00\"}")]
    [InlineData("{\"Origin\":\"http://localhost:5080\",\"AccessToken\":\"a\",\"ExpiresAt\":\"2000-01-01T00:00:00+00:00\",\"Username\":\"x\",\"RefreshToken\":\"\",\"RefreshExpiresAt\":\"2999-01-01T00:00:00+00:00\"}")]
    [InlineData("\0\0\0garbage")]
    public async Task Corrupt_token_files_mean_not_logged_in_never_a_crash(string content)
    {
        var dir = Path.Combine(Path.GetTempPath(), "gk-qa4c-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "token.json");
            File.WriteAllText(path, content);
            var store = new FileTokenStore(path);
            var r = await Run(_ => _factory.CreateClient(), store, null, "app", "list");
            _out.WriteLine($"exit={r.Code} {r.Err.Trim()}");
            Assert.Contains(r.Code, new[] { 5 });
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task A_token_directory_that_cannot_hold_the_lock_file_is_an_error_not_a_crash()
    {
        if (OperatingSystem.IsWindows() || Environment.UserName == "root") return;
        var dir = Path.Combine(Path.GetTempPath(), "gk-qa4c-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "token.json");
            var store = new FileTokenStore(path);
            store.Save(new StoredToken("http://localhost:5080", "a", DateTimeOffset.UtcNow.AddMinutes(-5), "bob", "gkr_x", DateTimeOffset.UtcNow.AddDays(1)));
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            var ex = await Record.ExceptionAsync(() => Run(_ => _factory.CreateClient(), store, null, "app", "list"));
            _out.WriteLine(ex?.GetType().FullName + ": " + ex?.Message);
            Assert.Null(ex);
        }
        finally { File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UserExec); Directory.Delete(dir, true); }
    }
    private const UnixFileMode UserExec = UnixFileMode.UserExecute;

    [Fact]
    public async Task A_lock_held_by_another_process_for_longer_than_15s_is_reported_cleanly()
    {
        var dir = Path.Combine(Path.GetTempPath(), "gk-qa4c-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var store = new FileTokenStore(Path.Combine(dir, "token.json"));
            store.Save(new StoredToken("http://localhost:5080", "a", DateTimeOffset.UtcNow.AddMinutes(-5), "bob", "gkr_x", DateTimeOffset.UtcNow.AddDays(1)));
            using var held = store.RefreshLock();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var ex = await Record.ExceptionAsync(() => Run(_ => _factory.CreateClient(), store, null, "app", "list"));
            _out.WriteLine($"{sw.Elapsed.TotalSeconds:F1}s {ex?.GetType().Name}: {ex?.Message}");
            Assert.Null(ex);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task Parallel_commands_with_the_real_file_store_share_one_refresh()
    {
        TestAuth.AdminToken(_factory);
        var dir = Path.Combine(Path.GetTempPath(), "gk-qa4c-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileTokenStore(Path.Combine(dir, "token.json"));
            Assert.Equal(0, (await Run(_ => _factory.CreateClient(), store, TestAuth.AdminPassword, "login", "--user", TestAuth.AdminName)).Code);
            store.Save(store.Load()! with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1), Origin = new Uri(_factory.Server.BaseAddress, "/").GetLeftPart(UriPartial.Authority) });
            var rs = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() =>
                Run(_ => _factory.CreateClient(), store, null, "--url", _factory.Server.BaseAddress.ToString(), "app", "list"))));
            foreach (var r in rs) _out.WriteLine($"{r.Code} {r.Err.Trim()}");
            Assert.All(rs, r => Assert.Equal(0, r.Code));
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
}
