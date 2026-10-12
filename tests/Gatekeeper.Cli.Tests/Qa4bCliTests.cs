using System.Net;
using System.Text;
using System.Text.Json;
using Gatekeeper.Cli;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Cli.Tests;

/// <summary>QA slice 4b: client and audit CLI commands.</summary>
[Collection("qa-env")]
public class Qa4bCliTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _f;
    private readonly MemoryTokenStore _tokens = new();
    private readonly string? _oldToken = Environment.GetEnvironmentVariable("GATEKEEPER_TOKEN");
    private readonly string? _oldUrl = Environment.GetEnvironmentVariable("GATEKEEPER_URL");

    public Qa4bCliTests(WebApplicationFactory<Program> f)
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

    private static string N(string p) => $"{p}{Guid.NewGuid():N}"[..16];

    private async Task<(int Code, string Out, string Err)> Gk(params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => _f.CreateAdminClient(), o, e, _tokens, (_, _) => null);
        return (code, o.ToString(), e.ToString());
    }

    private static async Task<(int Code, string Out, string Err)> GkFake(string body, params string[] args)
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(args, _ => new HttpClient(new Fixed(body)) { BaseAddress = new Uri("http://localhost:5080") }, o, e, new MemoryTokenStore(), (_, _) => null);
        return (code, o.ToString(), e.ToString());
    }

    private sealed class Fixed(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
    }

    [Fact]
    public async Task Create_prints_the_secret_once_on_stdout_and_keeps_stderr_for_the_hint()
    {
        var app = N("a"); var c = N("c");
        Assert.Equal(0, (await Gk("app", "create", app)).Code);
        var r = await Gk("client", "create", c, "--app", app);
        Assert.Equal(0, r.Code);
        Assert.Equal(1, r.Out.Split('\n').Count(l => l.StartsWith("secret: gks_")));
        var secret = r.Out.Split('\n').Single(l => l.StartsWith("secret: ")).Substring(8).Trim();
        Assert.DoesNotContain(secret, r.Err);
        foreach (var cmd in new[] { new[] { "client", "get", c }, new[] { "client", "list" }, new[] { "client", "roles", c }, new[] { "audit", "list" } })
        {
            var o = await Gk(cmd);
            Assert.DoesNotContain(secret, o.Out + o.Err);
        }
        // json mode: valid JSON on stdout with the secret, nothing on stderr
        var j = await Gk("--json", "client", "create", N("c"), "--app", app);
        Assert.Equal(0, j.Code);
        Assert.Equal("", j.Err);
        Assert.StartsWith("gks_", JsonDocument.Parse(j.Out).RootElement.GetProperty("secret").GetString());
        var rj = await Gk("--json", "client", "rotate-secret", c);
        Assert.Equal("", rj.Err);
        Assert.StartsWith("gks_", JsonDocument.Parse(rj.Out).RootElement.GetProperty("secret").GetString());
        var rt = await Gk("client", "rotate-secret", c);
        Assert.Contains("cannot be shown again", rt.Err);
    }

    [Fact]
    public async Task Exit_codes_for_client_commands()
    {
        var app = N("a"); var other = N("o"); var c = N("c");
        await Gk("app", "create", app); await Gk("app", "create", other);
        await Gk("role", "create", "r1", "--app", app); await Gk("role", "create", "r2", "--app", other);
        Assert.Equal(0, (await Gk("client", "create", c, "--app", app)).Code);
        Assert.Equal(3, (await Gk("client", "create", c, "--app", other)).Code);                // duplicate
        Assert.Equal(1, (await Gk("client", "create", "Bad Name", "--app", app)).Code);
        Assert.Equal(2, (await Gk("client", "create", N("x"), "--app", "no-such-app")).Code);
        Assert.Equal(3, (await Gk("client", "create", N("x"), "--app", "gatekeeper")).Code);   // reserved app
        Assert.Equal(2, (await Gk("client", "get", "nope")).Code);
        Assert.Equal(2, (await Gk("client", "get", Guid.NewGuid().ToString())).Code);
        Assert.Equal(2, (await Gk("client", "assign", c, "ghost-role")).Code);
        Assert.Equal(2, (await Gk("client", "assign", c, "r2")).Code);                           // role of another app is not found by name
        Assert.Equal(3, (await Gk("client", "assign", c, await RoleId(other, "r2"))).Code);     // ...and refused by id
        Assert.Equal(0, (await Gk("client", "assign", c.ToUpperInvariant(), "R1")).Code);       // case-insensitive both
        Assert.Equal(0, (await Gk("client", "assign", c, "r1")).Code);                          // idempotent
        Assert.Equal(0, (await Gk("client", "revoke", c, "r1")).Code);
        Assert.Equal(2, (await Gk("client", "revoke", c, "r1")).Code);
        Assert.Equal(2, (await Gk("client", "list", "--app", "no-such-app")).Code);
        Assert.Equal(2, (await Gk("client", "rotate-secret", "nope")).Code);
        Assert.Equal(2, (await Gk("client", "delete", "nope")).Code);
        Assert.Equal(0, (await Gk("client", "update", c)).Code);                                  // nothing to change is fine
        Assert.NotEqual(0, (await Gk("client", "update", c, "--active", "maybe")).Code);
        Assert.Equal(0, (await Gk("client", "update", c, "--active", "false")).Code);
        Assert.Contains("isActive: False", (await Gk("client", "get", c)).Out);
        Assert.Equal(0, (await Gk("client", "update", c, "--active", "true", "--name", c + "x")).Code);
        Assert.Equal(0, (await Gk("client", "delete", c + "x")).Code);
    }

    private static async Task Ok(Task<(int Code, string Out, string Err)> t, int expect = 0)
    {
        var r = await t;
        Assert.True(r.Code == expect, $"exit {r.Code} (want {expect}): {r.Err}{r.Out}");
    }

    private async Task<string> RoleId(string app, string role)
    {
        var o = await Gk("--json", "role", "list", "--app", app);
        return JsonDocument.Parse(o.Out).RootElement.EnumerateArray().Single(r => r.GetProperty("name").GetString() == role).GetProperty("id").GetString()!;
    }

    [Fact]
    public async Task Update_commands_use_patch_and_keep_unspecified_fields()
    {
        var app = N("a");
        await Gk("app", "create", app);
        await Gk("role", "create", "r1", "--app", app, "--description", "keep me");
        var u = N("u");
        await Gk("user", "create", u, "--email", u + "@example.com", "--display-name", "Keep Display");
        Assert.Equal(0, (await Gk("role", "update", "r1", "--app", app, "--name", "r2")).Code);
        Assert.Contains("keep me", (await Gk("role", "get", await RoleId(app, "r2"))).Out);
        Assert.Equal(0, (await Gk("user", "update", u, "--active", "false")).Code);
        var g = await Gk("user", "get", u);
        Assert.Contains("Keep Display", g.Out);
        Assert.Contains(u + "@example.com", g.Out);
        // clearing via empty string
        Assert.Equal(0, (await Gk("role", "update", "r2", "--app", app, "--description", "")).Code);
        Assert.DoesNotContain("keep me", (await Gk("role", "get", await RoleId(app, "r2"))).Out);
        Assert.Equal(0, (await Gk("user", "update", u, "--display-name", "")).Code);
        Assert.DoesNotContain("Keep Display", (await Gk("user", "get", u)).Out);
    }

    [Fact]
    public async Task Audit_action_filter_example_from_the_help_text_actually_matches()
    {
        var u = N("u");
        await Gk("user", "create", u, "--email", u + "@example.com");
        var id = JsonDocument.Parse((await Gk("--json", "user", "get", u)).Out).RootElement.GetProperty("id").GetString()!;
        var pw = new StringWriter();
        var code = await CliApp.RunAsync(["user", "set-password", u], _ => _f.CreateAdminClient(), pw, new StringWriter(), _tokens, (_, _) => "correct horse battery");
        Assert.Equal(0, code);
        var help = await Gk("audit", "list", "--help");
        Assert.Contains("PUT /v1/users/{id}/password", help.Out); // the documented example
        var r = await Gk("audit", "list", "--action", "PUT /v1/users/{id}/password");
        Assert.True(r.Out.Contains(id) || r.Out.Contains("PUT /v1/users"), "the --action example from --help finds nothing; stored text is '" + (await Gk("audit", "list", "--limit", "3")).Out.Split('\n')[0] + "'");
    }

    [Fact]
    public async Task Audit_list_options_and_errors()
    {
        await Gk("app", "create", N("a"));
        Assert.Equal(1, (await Gk("audit", "list", "--limit", "201")).Code);
        Assert.Equal(1, (await Gk("audit", "list", "--limit", "-1")).Code);
        Assert.NotEqual(0, (await Gk("audit", "list", "--limit", "abc")).Code);
        var one = await Gk("audit", "list", "--limit", "1");
        Assert.Equal(0, one.Code);
        Assert.Single(one.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        var j = await Gk("--json", "audit", "list", "--limit", "2");
        Assert.Equal(JsonValueKind.Array, JsonDocument.Parse(j.Out).RootElement.ValueKind);
        // odd filter values are escaped on the wire
        foreach (var a in new[] { "a&limit=1", "a b", "é", "x#y", "a=b", "100%" })
            Assert.Equal(0, (await Gk("audit", "list", "--actor", a)).Code);
    }

    [Fact]
    public async Task Output_from_a_hostile_server_is_sanitised_in_text_and_json_mode()
    {
        const string evil = "\u001b[31mRED\u001b]0;pwn\u0007 \u202Egpj.exe\r\nFAKE\u0085 \u2028 \u200B end";
        var audit = "{\"items\":[{\"at\":\"x\",\"outcome\":\"" + evil.Replace("\u001b", "\\u001b").Replace("\u0007", "\\u0007").Replace("\r\n", "\\r\\n").Replace("\u0085", "\\u0085").Replace("\u2028", "\\u2028") + "\",\"actor\":\"a\",\"action\":\"b\",\"target\":null,\"detail\":\"d\"}],\"nextCursor\":null}";
        var t = await GkFake(audit, "audit", "list");
        Assert.Equal(0, t.Code);
        foreach (var bad in new[] { '\u001b', '\u0007', '\r', '\u0085', '\u202E' })
            Assert.DoesNotContain(bad, t.Out);
        Assert.Single(t.Out.TrimEnd().Split('\n')); // no forged extra lines
        var clients = "{\"items\":[{\"id\":\"" + Guid.NewGuid() + "\",\"name\":\"\\u001b[2Jx\",\"appId\":\"y\",\"isActive\":true}],\"nextCursor\":null}";
        var c = await GkFake(clients, "client", "list");
        Assert.DoesNotContain('\u001b', c.Out);
        var cj = await GkFake(clients, "--json", "client", "list");
        Assert.DoesNotContain('\u001b', cj.Out);
        var bidi = await GkFake("{\"items\":[{\"at\":\"x\",\"outcome\":\"\\u202Eevil\",\"actor\":\"a\",\"action\":\"b\"}],\"nextCursor\":null}", "--json", "audit", "list");
        Assert.DoesNotContain('\u202E', bidi.Out);
        // wrong shapes never crash
        foreach (var body in new[] { "[]", "{}", "{\"items\":5}", "{\"items\":[5,\"x\",null]}", "null", "\"s\"", "" })
        {
            var r = await GkFake(body, "audit", "list");
            Assert.True(r.Code is 0 or 1, $"{body} -> {r.Code} {r.Err}");
        }
    }

    [Fact]
    public async Task Line_and_paragraph_separators_from_the_server_are_neutralised_like_the_server_does_itself()
    {
        var r = await GkFake("{\"items\":[{\"at\":\"x\",\"outcome\":\"a\\u2028b\\u2029c\",\"actor\":\"a\",\"action\":\"b\"}],\"nextCursor\":null}", "audit", "list");
        Assert.DoesNotContain('\u2028', r.Out);
        Assert.DoesNotContain('\u2029', r.Out);
    }

    [Fact]
    public async Task Client_commands_need_a_login_and_server_down_is_exit_4()
    {
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(["client", "list"], _ => _f.CreateClient(), o, e, new MemoryTokenStore(), (_, _) => null);
        Assert.Equal(5, code);
        code = await CliApp.RunAsync(["audit", "list"], _ => _f.CreateClient(), o, e, new MemoryTokenStore(), (_, _) => null);
        Assert.Equal(5, code);
        code = await CliApp.RunAsync(["--url", "http://127.0.0.1:1", "client", "list"], _ => new HttpClient { BaseAddress = new Uri("http://127.0.0.1:1") }, o, e, new MemoryTokenStore(), (_, _) => null);
        Assert.Equal(4, code);
    }
}
