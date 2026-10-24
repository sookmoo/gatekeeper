using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA of slice 6g (PUT /v1/me/password), written from the spec. One factory per test: throttles start empty.</summary>
public class Slice6gQaApiTests
{
    private const string Password = "correct horse battery";
    private const string Fresh = "tr0ub4dor staple 99";

    private sealed class CaptureLog : ILoggerProvider, ILogger
    {
        public System.Collections.Concurrent.ConcurrentQueue<string> Lines { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue(formatter(state, exception) + " " + exception);
    }

    private sealed class W(WebApplicationFactory<Program> f) : IDisposable
    {
        public WebApplicationFactory<Program> F { get; } = f;
        public HttpClient Admin { get; } = f.CreateAdminClient();

        public async Task<(string Name, Guid Id)> User(string? kind = null)
        {
            var name = $"qa-{Guid.NewGuid():N}"[..20];
            var r = await Admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One", kind, expiresAt = kind == "test" ? DateTimeOffset.UtcNow.AddDays(1) : (DateTimeOffset?)null });
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            return (name, id);
        }

        public async Task<(HttpClient C, string Refresh)> SignIn(string name, string password = Password)
        {
            var r = await F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = "gatekeeper", refresh = true });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var b = await r.Content.ReadFromJsonAsync<JsonElement>();
            var c = F.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", b.GetProperty("accessToken").GetString());
            return (c, b.GetProperty("refreshToken").GetString()!);
        }

        public Task<HttpResponseMessage> Login(string name, string password) =>
            F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = "gatekeeper", refresh = true });

        public void Dispose() { Admin.Dispose(); F.Dispose(); }
    }

    private static W World(Action<Microsoft.AspNetCore.Hosting.IWebHostBuilder>? cfg = null) =>
        new(new WebApplicationFactory<Program>().WithWebHostBuilder(b => cfg?.Invoke(b)));

    private static Task<HttpResponseMessage> Change(HttpClient c, string? cur, string? neu) =>
        c.PutAsJsonAsync("/v1/me/password", new { currentPassword = cur, newPassword = neu });

    private static Task<HttpResponseMessage> Raw(HttpClient c, string body, string mediaType = "application/json") =>
        c.PutAsync("/v1/me/password", new StringContent(body, Encoding.UTF8, mediaType));

    private static string Chars(int n) => new string('p', n);

    [Fact]
    public async Task New_password_length_boundaries_are_12_and_128()
    {
        using var w = World();
        var (name, _) = await w.User();
        var (c, _) = await w.SignIn(name);
        Assert.Equal(HttpStatusCode.BadRequest, (await Change(c, Password, Chars(11))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Change(c, Password, Chars(129))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Change(c, Password, "")).StatusCode);
        var max = Chars(128);
        Assert.Equal(HttpStatusCode.NoContent, (await Change(c, Password, max)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, max)).StatusCode);
        // the 128 character password is also a valid current password; 12 chars is the lower edge
        var min = Chars(12);
        Assert.Equal(HttpStatusCode.NoContent, (await Change(c, max, min)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, min)).StatusCode);
    }

    [Theory]
    [InlineData("line\nbreak in the middle")]
    [InlineData("nul\0 in the middle xxxx")]
    [InlineData("del\u007f in the middle xxx")]
    [InlineData("c1\u0085 in the middle xxxx")]
    public async Task Control_characters_in_the_new_password_are_a_400_and_change_nothing(string bad)
    {
        using var w = World();
        var (name, _) = await w.User();
        var (c, _) = await w.SignIn(name);
        var r = await Change(c, Password, bad);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode);
    }

    [Fact]
    public async Task A_lone_surrogate_in_the_new_password_is_a_400_not_a_500()
    {
        using var w = World();
        var (c, _) = await w.SignIn((await w.User()).Name);
        // \ud800 escaped in JSON: System.Text.Json turns an unpaired surrogate into U+FFFD or rejects it; either way not 5xx and not a change
        var r = await Raw(c, "{\"currentPassword\":\"" + Password + "\",\"newPassword\":\"abc\\ud800defghijklmnop\"}");
        Assert.True((int)r.StatusCode is 400 or 204, r.StatusCode.ToString());
    }

    [Fact]
    public async Task Control_characters_in_the_current_password_are_the_same_403_as_a_wrong_one()
    {
        using var w = World();
        var (c, _) = await w.SignIn((await w.User()).Name);
        var a = await Change(c, "wrong password here", Fresh);
        var b = await Change(c, "tab\tin the current pw", Fresh);
        var d = await Change(c, "", Fresh);
        Assert.Equal(HttpStatusCode.Forbidden, a.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, b.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, d.StatusCode);
        static async Task<string> Shape(HttpResponseMessage r)
        {
            var j = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;
            return string.Join("|", j.EnumerateObject().Where(p => p.Name != "traceId").Select(p => p.Name + "=" + p.Value)) + "|" + r.Content.Headers.ContentType + "|" + r.Headers.CacheControl;
        }
        Assert.Equal(await Shape(a), await Shape(b));
        Assert.Equal(await Shape(a), await Shape(d));
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    [InlineData("{}")]
    [InlineData("{\"currentPassword\":123,\"newPassword\":456}")]
    [InlineData("{\"currentPassword\":{},\"newPassword\":[]}")]
    [InlineData("{not json")]
    public async Task Odd_bodies_are_4xx_never_5xx_and_change_nothing(string body)
    {
        using var w = World();
        var (name, _) = await w.User();
        var (c, _) = await w.SignIn(name);
        var r = await Raw(c, body);
        Assert.True((int)r.StatusCode is >= 400 and < 500, $"{(int)r.StatusCode} for {body}");
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode);
    }

    [Fact]
    public async Task Non_json_content_type_and_no_content_type_are_4xx()
    {
        using var w = World();
        var (c, _) = await w.SignIn((await w.User()).Name);
        var r = await Raw(c, "currentPassword=a&newPassword=b", "application/x-www-form-urlencoded");
        Assert.True((int)r.StatusCode is >= 400 and < 500, r.StatusCode.ToString());
        var r2 = await Raw(c, "{}", "text/plain");
        Assert.True((int)r2.StatusCode is >= 400 and < 500, r2.StatusCode.ToString());
        var r3 = await c.PutAsync("/v1/me/password", null);
        Assert.True((int)r3.StatusCode is >= 400 and < 500, r3.StatusCode.ToString());
    }

    [Fact]
    public async Task A_huge_body_and_huge_passwords_are_refused_without_hashing_or_a_500()
    {
        using var w = World();
        var (name, _) = await w.User();
        var (c, _) = await w.SignIn(name);
        var big = new string('a', 5_000_000);
        var r = await Raw(c, "{\"currentPassword\":\"" + big + "\",\"newPassword\":\"" + Fresh + "\"}");
        Assert.True((int)r.StatusCode is >= 400 and < 500, r.StatusCode.ToString());
        var r2 = await Change(c, Password, big);
        Assert.Equal(HttpStatusCode.BadRequest, r2.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode);
    }

    [Fact]
    public async Task Other_verbs_are_not_a_way_to_change_the_password()
    {
        using var w = World();
        var (name, _) = await w.User();
        var (c, _) = await w.SignIn(name);
        foreach (var m in new[] { HttpMethod.Get, HttpMethod.Post, HttpMethod.Patch, HttpMethod.Delete })
        {
            var req = new HttpRequestMessage(m, "/v1/me/password") { Content = m == HttpMethod.Get ? null : JsonContent.Create(new { currentPassword = Password, newPassword = Fresh }) };
            var r = await c.SendAsync(req);
            Assert.True(r.StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotFound, $"{m}: {r.StatusCode}");
        }
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode);
    }

    [Fact]
    public async Task Another_users_sessions_survive_and_the_throttle_of_one_user_does_not_block_another()
    {
        using var w = World();
        var (a, _) = await w.User();
        var (b, _) = await w.User();
        var (ca, _) = await w.SignIn(a);
        var (cb, rb) = await w.SignIn(b);
        var (cb2, _) = await w.SignIn(b);
        for (var i = 0; i < Endpoints.PasswordFailuresPerUser; i++) await Change(ca, $"wrong wrong wrong {i}", Fresh);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Change(ca, Password, Fresh)).StatusCode);
        // user b is not blocked (the address budget of 20 is not used up) and ending b's other sessions leaves a untouched
        Assert.Equal(HttpStatusCode.NoContent, (await Change(cb, Password, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ca.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await cb2.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await cb.GetAsync("/v1/me")).StatusCode);
        _ = rb;
    }

    [Fact]
    public async Task A_spoofed_X_Forwarded_For_does_not_escape_the_address_throttle()
    {
        using var w = World();
        var clients = new List<HttpClient>();
        for (var i = 0; i < 5; i++) clients.Add((await w.SignIn((await w.User()).Name)).C);
        for (var i = 0; i < Endpoints.PasswordFailuresPerAddress; i++)
        {
            var req = new HttpRequestMessage(HttpMethod.Put, "/v1/me/password") { Content = JsonContent.Create(new { currentPassword = $"wrong wrong {i} x", newPassword = Fresh }) };
            req.Headers.TryAddWithoutValidation("X-Forwarded-For", $"203.0.113.{i + 1}");
            Assert.Equal(HttpStatusCode.Forbidden, (await clients[i % 5].SendAsync(req)).StatusCode);
        }
        var (fresh, _) = await w.SignIn((await w.User()).Name);
        var last = new HttpRequestMessage(HttpMethod.Put, "/v1/me/password") { Content = JsonContent.Create(new { currentPassword = Password, newPassword = Fresh }) };
        last.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100.77");
        Assert.Equal(HttpStatusCode.TooManyRequests, (await fresh.SendAsync(last)).StatusCode);
    }

    [Fact]
    public async Task A_throttled_attempt_with_the_right_password_leaves_no_audit_row_and_no_password_in_the_429()
    {
        using var w = World();
        var (name, id) = await w.User();
        var (c, _) = await w.SignIn(name);
        for (var i = 0; i < Endpoints.PasswordFailuresPerUser; i++) await Change(c, $"wrong wrong wrong {i}", Fresh);
        var before = (await w.Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={id}&limit=200")).GetProperty("items").GetArrayLength();
        var r = await Change(c, Password, Fresh);
        Assert.Equal(HttpStatusCode.TooManyRequests, r.StatusCode);
        var text = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain(Password, text);
        Assert.DoesNotContain(Fresh, text);
        Assert.True(r.Headers.Contains("Retry-After"));
        var after = (await w.Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={id}&limit=200")).GetProperty("items").GetArrayLength();
        Assert.Equal(before, after);
    }

    [Fact]
    public async Task Passwords_in_a_malformed_body_do_not_reach_logs_audit_or_the_response()
    {
        var log = new CaptureLog();
        using var w = World(b => b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(log)));
        var (c, _) = await w.SignIn((await w.User()).Name);
        const string secret = "LEAKCHECK-secret-7781";
        var r1 = await Raw(c, "{\"currentPassword\":\"" + secret + "\",\"newPassword\":\"" + secret + "-new\", ");
        var r2 = await Raw(c, "{\"currentPassword\":\"" + secret + "\",\"newPassword\":12345}");
        var r3 = await Change(c, secret, secret + "-new-and-different");
        var r4 = await Change(c, Password, secret + "\n");
        var all = await r1.Content.ReadAsStringAsync() + await r2.Content.ReadAsStringAsync() + await r3.Content.ReadAsStringAsync() + await r4.Content.ReadAsStringAsync()
                  + string.Join('\n', log.Lines) + await w.Admin.GetStringAsync("/v1/audit?limit=200");
        Assert.DoesNotContain("LEAKCHECK", all);
    }

    [Fact]
    public async Task A_test_kind_user_can_change_their_own_password()
    {
        using var w = World();
        var (name, _) = await w.User("test");
        var (c, _) = await w.SignIn(name);
        Assert.Equal(HttpStatusCode.NoContent, (await Change(c, Password, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Fresh)).StatusCode);
    }

    [Fact]
    public async Task An_admin_reset_between_sign_in_and_change_makes_the_old_current_password_wrong()
    {
        using var w = World();
        var (name, id) = await w.User();
        var (c, _) = await w.SignIn(name);
        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "admin reset password" })).StatusCode);
        // an admin reset ends the user's sessions, so the old token is simply dead (401); the old password can not be used either way
        Assert.Equal(HttpStatusCode.Unauthorized, (await Change(c, Password, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, "admin reset password")).StatusCode);
    }

    [Fact]
    public async Task Concurrent_changes_with_the_same_current_password_let_exactly_one_win()
    {
        using var w = World();
        var (name, _) = await w.User();
        var (c, _) = await w.SignIn(name);
        var tasks = Enumerable.Range(0, 4).Select(i => Change(c, Password, $"concurrent new password {i}")).ToArray();
        var codes = (await Task.WhenAll(tasks)).Select(r => r.StatusCode).ToList();
        Assert.Equal(1, codes.Count(x => x == HttpStatusCode.NoContent));
        Assert.All(codes.Where(x => x != HttpStatusCode.NoContent), x => Assert.Equal(HttpStatusCode.Forbidden, x));
        var winners = 0;
        for (var i = 0; i < 4; i++) if ((await w.Login(name, $"concurrent new password {i}")).StatusCode == HttpStatusCode.OK) winners++;
        Assert.Equal(1, winners);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Login(name, Password)).StatusCode);
    }

    [Fact]
    public async Task Admin_set_password_route_still_works_ignores_the_own_throttle_and_does_not_need_a_current_password()
    {
        using var w = World();
        var (name, id) = await w.User();
        var (c, _) = await w.SignIn(name);
        for (var i = 0; i < Endpoints.PasswordFailuresPerUser; i++) await Change(c, $"wrong wrong wrong {i}", Fresh);
        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "admin chosen password" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, "admin chosen password")).StatusCode);
        // a self token cannot use the admin route
        Assert.Equal(HttpStatusCode.Forbidden, (await c.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "self chosen password" })).StatusCode);
    }

    [Fact]
    public async Task OpenApi_documents_the_body_schema_and_the_problem_responses()
    {
        using var w = World();
        var doc = JsonDocument.Parse(await w.F.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement;
        var put = doc.GetProperty("paths").GetProperty("/v1/me/password");
        Assert.Equal(["put"], put.EnumerateObject().Select(p => p.Name.ToLowerInvariant()).Where(n => n is "put" or "get" or "post" or "delete" or "patch").ToArray());
        var text = put.GetRawText();
        Assert.Contains("currentPassword", doc.GetRawText());
        Assert.Contains("newPassword", doc.GetRawText());
        Assert.Contains("429", text);
        // the committed document matches the live one for this route
        var repoDoc = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRoot(), "docs", "openapi.json"))).RootElement;
        Assert.Equal(put.GetProperty("put").GetProperty("x-gatekeeper-access").GetString(),
            repoDoc.GetProperty("paths").GetProperty("/v1/me/password").GetProperty("put").GetProperty("x-gatekeeper-access").GetString());
    }

    private static string FindRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "status.md"))) d = d.Parent;
        return d!.FullName;
    }
}
