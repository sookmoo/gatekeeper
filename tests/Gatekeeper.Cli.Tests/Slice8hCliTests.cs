using System.Net;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class Slice8hCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public Slice8hCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    // Records every request that reaches the server (method, path, If-Match) and passes it on.
    private sealed class Recorder(HttpMessageHandler inner, List<(string Method, string Path, string? IfMatch)> log) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (log) log.Add((request.Method.Method, request.RequestUri!.AbsolutePath, request.Headers.TryGetValues("If-Match", out var v) ? string.Join(",", v) : null));
            return base.SendAsync(request, ct);
        }
    }

    private async Task<(int Code, string Out, string Err, List<(string Method, string Path, string? IfMatch)> Log)> Gk(params string[] args)
    {
        TestAuth.AdminToken(_factory);
        var log = new List<(string, string, string?)>();
        var o = new StringWriter(); var e = new StringWriter();
        var tokens = new MemoryTokenStore();
        var login = await CliApp.RunAsync(["login", "--user", TestAuth.AdminName], _ => _factory.CreateClient(), new StringWriter(), new StringWriter(), tokens, (_, _) => TestAuth.AdminPassword);
        Assert.Equal(0, login);
        var code = await CliApp.RunAsync(args, _ => new HttpClient(new Recorder(_factory.Server.CreateHandler(), log)) { BaseAddress = _factory.Server.BaseAddress }, o, e, tokens, (_, _) => null);
        return (code, o.ToString(), e.ToString(), log);
    }

    private static string Name(string p) => $"{p}-{Guid.NewGuid():N}"[..16];

    private async Task<long> VersionOf(string kind, string name)
    {
        var r = await Gk(kind, "get", name, "--json");
        Assert.Equal(0, r.Code);
        return JsonDocument.Parse(r.Out).RootElement.GetProperty("version").GetInt64();
    }

    [Fact]
    public async Task Get_shows_the_version_to_use_with_if_version()
    {
        var app = Name("v8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var shown = await Gk("app", "get", app);
        Assert.Contains("version", shown.Out);
    }

    [Fact]
    public async Task Update_with_the_current_version_sends_if_match_and_succeeds_and_a_stale_one_is_412_exit_3()
    {
        var app = Name("v8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var v = await VersionOf("app", app);

        var ok = await Gk("app", "update", app, "--name", app + "x", "--if-version", v.ToString());
        Assert.Equal(0, ok.Code);
        var patch = ok.Log.Single(l => l.Method == "PATCH");
        Assert.Equal($"\"{v}\"", patch.IfMatch);

        var stale = await Gk("app", "update", app + "x", "--name", app + "y", "--if-version", v.ToString());
        Assert.Equal(3, stale.Code);
        Assert.Contains("another version", stale.Err);
        Assert.Contains("get", stale.Err);
        Assert.Equal(0, (await Gk("app", "get", app + "x")).Code); // not renamed by the failed update
    }

    [Fact]
    public async Task Delete_with_if_version_sends_if_match_and_a_stale_version_deletes_nothing()
    {
        var app = Name("v8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var v = await VersionOf("app", app);
        var stale = await Gk("app", "delete", app, "--if-version", (v + 1).ToString());
        Assert.Equal(3, stale.Code);
        Assert.Equal($"\"{v + 1}\"", stale.Log.Single(l => l.Method == "DELETE").IfMatch);
        Assert.Equal(0, (await Gk("app", "get", app)).Code);
        var ok = await Gk("app", "delete", app, "--if-version", v.ToString());
        Assert.Equal(0, ok.Code);
        Assert.Equal($"\"{v}\"", ok.Log.Single(l => l.Method == "DELETE").IfMatch);
        Assert.Equal(2, (await Gk("app", "get", app)).Code);
    }

    [Fact]
    public async Task Without_the_flag_no_if_match_is_sent()
    {
        var app = Name("v8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var r = await Gk("app", "update", app, "--name", app + "x");
        Assert.Equal(0, r.Code);
        Assert.Null(r.Log.Single(l => l.Method == "PATCH").IfMatch);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-3")]
    [InlineData("abc")]
    [InlineData("1.5")]
    public async Task A_bad_if_version_is_refused_before_anything_is_sent(string value)
    {
        var app = Name("v8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var r = await Gk("app", "delete", app, "--if-version", value);
        Assert.NotEqual(0, r.Code);
        Assert.Contains("if-version", r.Err, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(r.Log, l => l.Method == "DELETE");
        Assert.Equal(0, (await Gk("app", "get", app)).Code);
    }

    [Fact]
    public async Task Roles_users_and_clients_take_the_flag_too()
    {
        var app = Name("v8h"); var user = Name("u8h"); var client = Name("c8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        Assert.Equal(0, (await Gk("role", "create", "editor", "--app", app)).Code);
        Assert.Equal(0, (await Gk("user", "create", user, "--email", user + "@example.com")).Code);
        Assert.Equal(0, (await Gk("client", "create", client, "--app", app)).Code);

        var role = await Gk("role", "update", "editor", "--app", app, "--description", "d", "--if-version", "1");
        Assert.Equal(0, role.Code);
        Assert.Equal("\"1\"", role.Log.Single(l => l.Method == "PATCH").IfMatch);
        Assert.Equal(3, (await Gk("role", "update", "editor", "--app", app, "--description", "e", "--if-version", "1")).Code);
        Assert.Equal(3, (await Gk("role", "delete", "editor", "--app", app, "--if-version", "1")).Code);

        var u = await Gk("user", "update", user, "--display-name", "X", "--if-version", "1");
        Assert.Equal(0, u.Code);
        Assert.Equal("\"1\"", u.Log.Single(l => l.Method == "PATCH").IfMatch);
        Assert.Equal(3, (await Gk("user", "delete", user, "--if-version", "1")).Code);
        Assert.Equal(0, (await Gk("user", "delete", user, "--if-version", (await VersionOf("user", user)).ToString())).Code);

        var c = await Gk("client", "update", client, "--active", "false", "--if-version", "1");
        Assert.Equal(0, c.Code);
        Assert.Equal(3, (await Gk("client", "delete", client, "--if-version", "1")).Code);
        Assert.Equal(0, (await Gk("client", "delete", client, "--if-version", (await VersionOf("client", client)).ToString())).Code);
    }
}
