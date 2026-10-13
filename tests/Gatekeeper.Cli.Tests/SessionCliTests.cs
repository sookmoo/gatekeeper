using System.Net.Http.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class SessionCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public SessionCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private async Task<(int Code, string Out, string Err)> Gk(ITokenStore tokens, string? secret, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _factory.CreateClient(), o, e, tokens, (_, _) => secret);
        return (code, o.ToString(), e.ToString());
    }

    private async Task<MemoryTokenStore> LoggedIn()
    {
        TestAuth.AdminToken(_factory);
        var tokens = new MemoryTokenStore();
        Assert.Equal(0, (await Gk(tokens, TestAuth.AdminPassword, "login", "--user", TestAuth.AdminName)).Code);
        return tokens;
    }

    private static void Age(MemoryTokenStore t) => t.Save(t.Current! with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) });

    [Fact]
    public async Task Login_saves_a_refresh_token_and_an_expired_access_token_is_renewed_silently()
    {
        var tokens = await LoggedIn();
        var first = tokens.Current!;
        Assert.StartsWith("gkr_", first.RefreshToken);
        Assert.True(first.RefreshExpiresAt > DateTimeOffset.UtcNow.AddDays(29));

        Age(tokens);
        Assert.Equal(0, (await Gk(tokens, null, "app", "list")).Code);
        var renewed = tokens.Current!;
        Assert.NotEqual(first.AccessToken, renewed.AccessToken);
        Assert.NotEqual(first.RefreshToken, renewed.RefreshToken); // rotated
        Assert.True(renewed.ExpiresAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Commands_running_at_the_same_time_do_not_trip_the_reuse_detection()
    {
        var tokens = await LoggedIn();
        Age(tokens);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => Gk(tokens, null, "app", "list"))));
        Assert.All(results, r => Assert.Equal(0, r.Code));
        Age(tokens);
        Assert.Equal(0, (await Gk(tokens, null, "app", "list")).Code); // the session is still alive
    }

    [Fact]
    public async Task Logout_ends_the_session_on_the_server_too()
    {
        var tokens = await LoggedIn();
        var stolenCopy = tokens.Current!.RefreshToken!;
        Assert.Equal(0, (await Gk(tokens, null, "logout")).Code);
        Assert.Null(tokens.Current);
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = stolenCopy });
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task A_revoked_session_means_exit_5_and_the_saved_login_is_removed()
    {
        var tokens = await LoggedIn();
        var other = new MemoryTokenStore();
        Assert.Equal(0, (await Gk(other, TestAuth.AdminPassword, "login", "--user", TestAuth.AdminName)).Code);
        Assert.Equal(0, (await Gk(other, null, "user", "revoke-sessions", TestAuth.AdminName)).Code); // ends both sessions

        Age(tokens);
        var r = await Gk(tokens, null, "app", "list");
        Assert.Equal(5, r.Code);
        Assert.Null(tokens.Current);
    }

    [Fact]
    public async Task Sessions_can_be_listed_and_revoked_from_the_cli()
    {
        var tokens = await LoggedIn();
        var list = await Gk(tokens, null, "user", "sessions", TestAuth.AdminName);
        Assert.Equal(0, list.Code);
        Assert.NotEmpty(list.Out.Trim());
        Assert.DoesNotContain(tokens.Current!.RefreshToken!, list.Out);
        var revoke = await Gk(tokens, null, "user", "revoke-sessions", TestAuth.AdminName);
        Assert.Equal(0, revoke.Code);
        Assert.Contains("revoked", revoke.Out);
    }

    [Fact]
    public async Task A_file_token_store_round_trips_refresh_fields_and_still_reads_old_files()
    {
        var dir = Path.Combine(Path.GetTempPath(), "gk-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "token.json");
            var store = new FileTokenStore(path);
            var t = new StoredToken("http://localhost:5080", "a", DateTimeOffset.UtcNow, "bob", "gkr_x", DateTimeOffset.UtcNow.AddDays(1));
            store.Save(t);
            Assert.Equal(t.RefreshToken, store.Load()!.RefreshToken);
            File.WriteAllText(path, """{"Origin":"http://localhost:5080","AccessToken":"a","ExpiresAt":"2030-01-01T00:00:00+00:00","Username":"bob"}""");
            var old = store.Load();
            Assert.NotNull(old);
            Assert.Null(old!.RefreshToken);
            using (store.RefreshLock()) { }
            using (store.RefreshLock()) { } // released again
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }
}
