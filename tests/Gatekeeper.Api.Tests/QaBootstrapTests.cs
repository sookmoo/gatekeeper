using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Api.Tests;

/// <summary>QA slice 4a: the bootstrap-admin command (run as a real process) and Auth:SeedDevAdmin.</summary>
public class QaBootstrapTests
{
    private const string Pw = "bootstrap password 1";

    private static (int Code, string Out, string Err) RunApi(string[] args, Dictionary<string, string?> env, string? stdin)
    {
        var psi = new ProcessStartInfo("dotnet") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Gatekeeper.Api.dll"));
        foreach (var a in args) psi.ArgumentList.Add(a);
        foreach (var kv in env) { if (kv.Value is null) psi.Environment.Remove(kv.Key); else psi.Environment[kv.Key] = kv.Value; }
        psi.Environment.Remove("GATEKEEPER_BOOTSTRAP_PASSWORD");
        foreach (var kv in env) if (kv.Value is not null) psi.Environment[kv.Key] = kv.Value;
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
        if (stdin is not null) p.StandardInput.Write(stdin);
        p.StandardInput.Close();
        if (!p.WaitForExit(60_000)) { p.Kill(true); throw new TimeoutException("process hung: " + string.Join(' ', args)); }
        return (p.ExitCode, o.Result, e.Result);
    }

    private sealed class Pg : IDisposable
    {
        public PgTestDatabase Db;
        public WebApplicationFactory<Program> Factory;
        public Pg()
        {
            Db = PgTestDatabase.TryCreate()!;
            Skip.If(Db is null, "GATEKEEPER_TEST_PG is not set");
            using (var m = new ServiceCollection().AddPostgresStore(Db.MigratorConnection).BuildServiceProvider())
                PostgresStoreExtensions.MigrateAsync(m).GetAwaiter().GetResult();
            Db.GrantAppAccess();
            Factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            {
                b.UseSetting("Store:Provider", "Postgres");
                b.UseSetting("Auth:SigningKeyPem", TestKey.Pem);
                b.UseSetting("ConnectionStrings:Gatekeeper", Db.AppConnection);
            });
        }
        public Dictionary<string, string?> Env => new()
        {
            ["Store__Provider"] = "Postgres",
            ["ConnectionStrings__Gatekeeper"] = Db.AppConnection,
        };
        public void Dispose() { Factory.Dispose(); Db.Dispose(); }
    }

    [SkippableFact]
    public async Task Bootstrap_creates_a_working_administrator_and_is_repeatable_for_other_users()
    {
        using var pg = new Pg();
        var r = RunApi(["bootstrap-admin", "root1", "root1@example.com"], pg.Env, Pw + "\n");
        Assert.True(r.Code == 0, r.Err);
        Assert.DoesNotContain(Pw, r.Out + r.Err);

        var anon = pg.Factory.CreateClient();
        var login = await anon.PostAsJsonAsync("/v1/auth/login", new { username = "root1", password = Pw, application = "gatekeeper" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        var admin = pg.Factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new("Bearer", token);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/v1/applications")).StatusCode);

        // second run, same user: repairs it (the recovery path): password reset, still an administrator
        var again = RunApi(["bootstrap-admin", "root1", "root1@example.com"], pg.Env, "another password 22\n");
        Assert.True(again.Code == 0, again.Err);
        Assert.Contains("already existed", again.Out);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = "root1", password = Pw, application = "gatekeeper" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = "root1", password = "another password 22", application = "gatekeeper" })).StatusCode);

        // a second administrator reuses the existing app and role (no duplicates, no conflict)
        var second = RunApi(["bootstrap-admin", "root2", "root2@example.com"], pg.Env, "second admin pw 33\r\n");
        Assert.True(second.Code == 0, second.Err);
        var apps = await (await admin.GetAsync("/v1/applications")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, apps.GetProperty("items").EnumerateArray().Count(a => a.GetProperty("name").GetString() == "gatekeeper"));
        var gk = apps.GetProperty("items").EnumerateArray().First(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await (await admin.GetAsync($"/v1/applications/{gk}/roles")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, roles.GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = "root2", password = "second admin pw 33", application = "gatekeeper" })).StatusCode);
    }

    [SkippableFact]
    public async Task Bootstrap_repairs_an_admin_role_stored_with_other_casing()
    {
        using var pg = new Pg();
        var anon = pg.Factory.CreateClient();
        var apps = pg.Factory.Services.GetRequiredService<Gatekeeper.Application.IAppRepository>();
        var roleRepo = pg.Factory.Services.GetRequiredService<Gatekeeper.Application.IRoleRepository>();
        var app = await apps.AddAsync(new Gatekeeper.Domain.App(Guid.NewGuid(), "gatekeeper"));
        await roleRepo.AddAsync(new Gatekeeper.Domain.Role(Guid.NewGuid(), app.Id, "ADMIN", "old"));

        var r = RunApi(["bootstrap-admin", "root3", "root3@example.com"], pg.Env, Pw + "\n");
        Assert.True(r.Code == 0, r.Err);
        var stored = await roleRepo.ListByAppAsync(app.Id);
        Assert.Equal("admin", Assert.Single(stored).Name);

        var login = await anon.PostAsJsonAsync("/v1/auth/login", new { username = "root3", password = Pw, application = "gatekeeper" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var admin = pg.Factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/v1/applications")).StatusCode);
    }

    [SkippableFact]
    public async Task Bootstrap_rejects_bad_input_without_leaving_a_half_created_admin()
    {
        using var pg = new Pg();
        var cases = new (string[] Args, string? Stdin, int Code)[]
        {
            (["bootstrap-admin", "bad1", "bad1@example.com"], "short\n", 1),
            (["bootstrap-admin", "bad1", "bad1@example.com"], "", 1),
            (["bootstrap-admin", "bad1", "bad1@example.com"], "\n", 1),
            (["bootstrap-admin", "bad1", "bad1@example.com"], new string('x', 129) + "\n", 1),
            (["bootstrap-admin", "Bad1", "bad1@example.com"], Pw + "\n", 1),
            (["bootstrap-admin", "bad1", "not-an-email"], Pw + "\n", 1),
            (["bootstrap-admin", "bad1"], Pw + "\n", 1),
            (["bootstrap-admin", "bad1", "bad1@example.com", "extra"], Pw + "\n", 1),
            (["bootstrap-admin"], Pw + "\n", 1),
        };
        foreach (var (args, stdin, code) in cases)
        {
            var r = RunApi(args, pg.Env, stdin);
            Assert.True(r.Code == code, $"{string.Join(' ', args)} / '{stdin?.Length}' -> {r.Code} {r.Err}");
            Assert.DoesNotContain("   at ", r.Err);        // no stack trace
        }
        var admin = pg.Factory.CreateAdminClient();
        var users = await (await admin.GetAsync("/v1/users")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, users.GetProperty("items").GetArrayLength()); // only test-admin, created for the client above
        // a conflicting email is a clean error, not a crash
        Assert.Equal(0, RunApi(["bootstrap-admin", "good1", "same@example.com"], pg.Env, Pw + "\n").Code);
        var clash = RunApi(["bootstrap-admin", "good2", "SAME@example.com"], pg.Env, Pw + "\n");
        Assert.Equal(1, clash.Code);
        Assert.DoesNotContain("   at ", clash.Err);
        users = await (await admin.GetAsync("/v1/users")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, users.GetProperty("items").GetArrayLength()); // test-admin and good1
    }

    [SkippableFact]
    public async Task Bootstrap_password_from_environment_wins_over_stdin_and_works_with_a_closed_stdin()
    {
        using var pg = new Pg();
        var env = pg.Env; env["GATEKEEPER_BOOTSTRAP_PASSWORD"] = "from the environment 1";
        var r = RunApi(["bootstrap-admin", "envadm", "envadm@example.com"], env, "ignored stdin password\n");
        Assert.True(r.Code == 0, r.Err);
        var anon = pg.Factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = "envadm", password = "from the environment 1", application = "gatekeeper" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = "envadm", password = "ignored stdin password", application = "gatekeeper" })).StatusCode);
    }

    [Fact]
    public void Bootstrap_and_dev_seed_refuse_unsuitable_stores_cleanly()
    {
        var mem = new Dictionary<string, string?> { ["Store__Provider"] = "InMemory" };
        var r = RunApi(["bootstrap-admin", "x1", "x1@example.com"], mem, Pw + "\n");
        Assert.Equal(1, r.Code);
        Assert.DoesNotContain("   at ", r.Err);

        var seedPg = RunApi([], new() { ["Store__Provider"] = "Postgres", ["ConnectionStrings__Gatekeeper"] = "Host=127.0.0.1;Port=1;Username=x;Password=y;Database=z;Timeout=1",
            ["Auth__SigningKeyPem"] = TestKey.Pem, ["Auth__SeedDevAdmin"] = "true" }, null);
        Assert.Equal(1, seedPg.Code);
        Assert.Contains("SeedDevAdmin", seedPg.Err);

        var unknown = RunApi([], new() { ["Store__Provider"] = "Nope" }, null);
        Assert.Equal(1, unknown.Code);
    }

    private sealed class Capture : ILoggerProvider, ILogger
    {
        public readonly List<string> Lines = [];
        public ILogger CreateLogger(string c) => this;
        public IDisposable? BeginScope<T>(T state) where T : notnull => null;
        public bool IsEnabled(LogLevel l) => true;
        public void Log<T>(LogLevel l, EventId id, T s, Exception? ex, Func<T, Exception?, string> f) { lock (Lines) Lines.Add(f(s, ex)); }
        public void Dispose() { }
    }

    [Fact]
    public async Task Dev_seed_creates_a_logging_in_admin_with_a_fresh_random_password_each_start()
    {
        var passwords = new List<string>();
        for (var i = 0; i < 2; i++)
        {
            var log = new Capture();
            using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            {
                b.UseSetting("Auth:SeedDevAdmin", "true");
                b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(log));
            });
            var c = f.CreateClient();
            string line;
            lock (log.Lines) line = log.Lines.Single(l => l.Contains("Development administrator"));
            var pw = Regex.Match(line, @"Password: (\S+)").Groups[1].Value;
            Assert.True(pw.Length >= 12, "dev password too short: " + pw.Length);
            passwords.Add(pw);
            var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = "admin", password = pw, application = "gatekeeper" });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var token = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
            c.DefaultRequestHeaders.Authorization = new("Bearer", token);
            Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/v1/users")).StatusCode);
            // the password is only in the log line, never in the API
            Assert.DoesNotContain(pw, await c.GetStringAsync("/v1/users"));
            // the seeded admin is protected like any other: the reserved app cannot be deleted
            var apps = await c.GetFromJsonAsync<JsonElement>("/v1/applications");
            var id = apps.GetProperty("items").EnumerateArray().Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.Conflict, (await c.DeleteAsync($"/v1/applications/{id}")).StatusCode);
            // and so are its roles: no create, no change (not even the description), no delete
            Assert.Equal(HttpStatusCode.Conflict, (await c.PostAsJsonAsync($"/v1/applications/{id}/roles", new { name = "extra" })).StatusCode);
            var role = (await c.GetFromJsonAsync<JsonElement>($"/v1/applications/{id}/roles")).GetProperty("items").EnumerateArray().Single();
            var rid = role.GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.Conflict, (await c.PutAsJsonAsync($"/v1/roles/{rid}", new { name = "admin", description = "tampered" })).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await c.SendAsync(new HttpRequestMessage(HttpMethod.Patch, $"/v1/roles/{rid}") { Content = JsonContent.Create(new { description = "tampered" }) })).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await c.DeleteAsync($"/v1/roles/{rid}")).StatusCode);
            Assert.Equal(role.GetProperty("description").GetString(), (await c.GetFromJsonAsync<JsonElement>($"/v1/roles/{rid}")).GetProperty("description").GetString());
        }
        Assert.NotEqual(passwords[0], passwords[1]);
    }

    [Fact]
    public async Task Without_the_seed_flag_nobody_exists_and_nothing_is_logged_about_a_password()
    {
        var log = new Capture();
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(log)));
        var c = f.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsJsonAsync("/v1/auth/login", new { username = "admin", password = "anything at all 1", application = "gatekeeper" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/users")).StatusCode);
        lock (log.Lines) Assert.DoesNotContain(log.Lines, l => l.Contains("Password:"));
    }

    [Fact]
    public async Task Logs_never_contain_submitted_passwords_or_tokens()
    {
        var log = new Capture();
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(log)));
        var admin = f.CreateAdminClient();
        var token = admin.DefaultRequestHeaders.Authorization!.Parameter!;
        var id = (await (await admin.PostAsJsonAsync("/v1/users", new { username = "logcheck", email = "logcheck@example.com" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "super secret value 77" });
        await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = "logcheck", password = "wrong secret value 88", application = "gatekeeper" });
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "short" }); // 400 path
        lock (log.Lines)
        {
            Assert.DoesNotContain(log.Lines, l => l.Contains("super secret value 77") || l.Contains("wrong secret value 88") || l.Contains(token) || l.Contains("short\""));
        }
    }
}
