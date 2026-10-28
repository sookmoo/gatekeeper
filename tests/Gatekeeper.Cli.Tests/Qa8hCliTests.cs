using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

public class Qa8hCliTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public Qa8hCliTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private sealed class Rec(HttpMessageHandler inner, List<string> log) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            lock (log) log.Add($"{r.Method} {r.RequestUri!.AbsolutePath} {(r.Headers.TryGetValues("If-Match", out var v) ? string.Join(",", v) : "-")}");
            return base.SendAsync(r, ct);
        }
    }

    private async Task<(int Code, string Out, string Err, List<string> Log)> Gk(params string[] args)
    {
        TestAuth.AdminToken(_factory);
        var log = new List<string>();
        var o = new StringWriter(); var e = new StringWriter(); var tokens = new MemoryTokenStore();
        Assert.Equal(0, await CliApp.RunAsync(["login", "--user", TestAuth.AdminName], _ => _factory.CreateClient(), new StringWriter(), new StringWriter(), tokens, (_, _) => TestAuth.AdminPassword));
        var code = await CliApp.RunAsync(args, _ => new HttpClient(new Rec(_factory.Server.CreateHandler(), log)) { BaseAddress = _factory.Server.BaseAddress }, o, e, tokens, (_, _) => null);
        return (code, o.ToString(), e.ToString(), log);
    }

    private static string Name(string p) => $"{p}-{Guid.NewGuid():N}"[..16];

    [Theory]
    [InlineData("+1")]
    [InlineData(" 1")]
    [InlineData("99999999999999999999")]
    [InlineData("")]
    [InlineData("1e3")]
    [InlineData("0x1")]
    [InlineData("\u0661")] // arabic-indic digit one
    public async Task Odd_if_version_values_are_refused_without_a_request(string value)
    {
        var app = Name("q8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var r = await Gk("app", "delete", app, "--if-version", value);
        Assert.NotEqual(0, r.Code);
        Assert.DoesNotContain(r.Log, l => l.StartsWith("DELETE"));
    }

    [Fact]
    public async Task Equals_syntax_and_max_long_work_and_missing_value_is_an_error()
    {
        var app = Name("q8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var eq = await Gk("app", "delete", app, "--if-version=9223372036854775807");
        Assert.Equal(3, eq.Code);
        Assert.Contains(eq.Log, l => l == $"DELETE {eq.Log.First(x => x.StartsWith("DELETE")).Split(' ')[1]} \"9223372036854775807\"");
        var missing = await Gk("app", "delete", app, "--if-version");
        Assert.NotEqual(0, missing.Code);
        Assert.DoesNotContain(missing.Log, l => l.StartsWith("DELETE"));
    }

    [Fact]
    public async Task Repeating_the_flag_does_not_send_a_malformed_header()
    {
        var app = Name("q8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var r = await Gk("app", "delete", app, "--if-version", "1", "--if-version", "2");
        foreach (var l in r.Log.Where(l => l.StartsWith("DELETE"))) Assert.Matches("\"\\d+\"$", l);
    }

    [Fact]
    public async Task Json_output_carries_version_and_table_keeps_old_columns_first()
    {
        var app = Name("q8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var json = await Gk("app", "get", app, "--json");
        Assert.Equal(1, JsonDocument.Parse(json.Out).RootElement.GetProperty("version").GetInt64());
        var table = await Gk("app", "list");
        var row = table.Out.Split('\n').First(l => l.Contains(app)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal([app, "1"], row.Skip(1).Take(2)); // id, name, version (no header row)
    }

    [Fact]
    public async Task A_412_on_update_names_exit_3_and_json_mode_does_not_print_a_result()
    {
        var app = Name("q8h");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var r = await Gk("app", "update", app, "--name", app + "z", "--if-version", "7", "--json");
        Assert.Equal(3, r.Code);
        Assert.Equal("", r.Out.Trim());
        Assert.Contains("another version", r.Err);
    }
}
