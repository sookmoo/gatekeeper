using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6g: PUT /v1/me/password. Every test has its own factory, so the in-process throttles start empty.</summary>
public class Slice6gApiTests
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

    private sealed class World(WebApplicationFactory<Program> factory) : IDisposable
    {
        public WebApplicationFactory<Program> Factory { get; } = factory;
        public HttpClient Admin { get; } = factory.CreateAdminClient();

        public async Task<(string Name, Guid Id)> NewUser(string? kind = null, string password = Password, bool setPassword = true)
        {
            var name = $"usr-{Guid.NewGuid():N}"[..20];
            var r = await Admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One", kind, expiresAt = kind == "test" ? DateTimeOffset.UtcNow.AddDays(1) : (DateTimeOffset?)null });
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
            if (setPassword) Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password })).StatusCode);
            return (name, id);
        }

        public async Task<(HttpClient Client, string Refresh)> SignIn(string name, string password = Password)
        {
            var r = await Factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = "gatekeeper", refresh = true });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var body = await r.Content.ReadFromJsonAsync<JsonElement>();
            var c = Factory.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("accessToken").GetString());
            return (c, body.GetProperty("refreshToken").GetString()!);
        }

        public Task<HttpResponseMessage> Login(string name, string password) =>
            Factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = "gatekeeper", refresh = true });

        public Task<HttpResponseMessage> Refresh(string token) => Factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = token });

        public async Task<List<JsonElement>> Audit(Guid actor) =>
            (await Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=200")).GetProperty("items").EnumerateArray().ToList();

        public void Dispose()
        {
            Admin.Dispose();
            Factory.Dispose();
        }
    }

    private static World NewWorld(Action<Microsoft.AspNetCore.Hosting.IWebHostBuilder>? configure = null) =>
        new(new WebApplicationFactory<Program>().WithWebHostBuilder(b => configure?.Invoke(b)));

    private static Task<HttpResponseMessage> Change(HttpClient c, string? current, string? replacement) =>
        c.PutAsJsonAsync("/v1/me/password", new { currentPassword = current, newPassword = replacement });

    private static async Task<string> Problem(HttpResponseMessage r)
    {
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        var code = body.TryGetProperty("code", out var c) ? c.GetString() : "";
        var detail = body.TryGetProperty("detail", out var d) ? d.GetString() : "";
        return $"{(int)r.StatusCode}|{code}|{detail}";
    }

    [Fact]
    public async Task A_correct_current_password_changes_it_ends_the_other_sessions_and_keeps_the_current_one()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (current, currentRefresh) = await w.SignIn(name);
        var (_, otherRefresh) = await w.SignIn(name);
        var (otherClient, _) = await w.SignIn(name);
        var etagBefore = (await w.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag;

        var r = await Change(current, Password, Fresh);
        Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString());

        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Login(name, Password)).StatusCode); // the old password is gone
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await current.GetAsync("/v1/me")).StatusCode); // the current session stays
        Assert.Equal(HttpStatusCode.OK, (await w.Refresh(currentRefresh)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Refresh(otherRefresh)).StatusCode); // the others are over
        Assert.Equal(HttpStatusCode.Unauthorized, (await otherClient.GetAsync("/v1/me")).StatusCode); // their access tokens stop at once (cache evicted)

        // The password is a separate resource (6d): the user's version and ETag do not move.
        Assert.Equal(etagBefore, (await w.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag);
    }

    [Fact]
    public async Task A_wrong_current_password_is_a_fixed_403_that_changes_nothing_and_keeps_the_session()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (client, refresh) = await w.SignIn(name);
        var etagBefore = (await w.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag;

        var r = await Change(client, "not the password at all", Fresh);
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal($"403|{Endpoints.WrongCurrentPasswordCode}|{Endpoints.WrongCurrentPasswordText}", await Problem(r));
        Assert.False(r.Headers.Contains("WWW-Authenticate")); // not a 401: the token is fine
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode); // nothing changed
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Login(name, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Refresh(refresh)).StatusCode);
        Assert.Equal(etagBefore, (await w.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag);
    }

    [Fact]
    public async Task Every_reason_the_current_password_is_not_accepted_gives_the_same_answer()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        var answers = new List<string>();
        foreach (var current in new[] { "not the password at all", "short", new string('x', 129), Password.ToUpperInvariant(), Password + " " })
            answers.Add(await Problem(await Change(client, current, Fresh)));
        Assert.Single(answers.Distinct());

        // A user that never had a password, with a validly signed token: same answer, same hash work.
        var (bare, bareId) = await w.NewUser(setPassword: false);
        var bareClient = w.Factory.CreateClient();
        bareClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(w.Factory,
            new User(bareId, bare, bare + "@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "gatekeeper", []));
        Assert.Equal(answers[0], await Problem(await Change(bareClient, "another wrong password", Fresh)));
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode);
        _ = id;
    }

    [Fact]
    public async Task A_new_password_equal_to_the_current_one_is_refused_with_a_fixed_400_and_changes_nothing()
    {
        using var w = NewWorld();
        var (name, _) = await w.NewUser();
        var (client, refresh) = await w.SignIn(name);
        var (_, otherRefresh) = await w.SignIn(name);
        var r = await Change(client, Password, Password);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("must differ from the current password.", body.GetProperty("errors").GetProperty("newPassword")[0].GetString());
        Assert.Equal(HttpStatusCode.OK, (await w.Refresh(otherRefresh)).StatusCode); // no session was ended
        // ...and a wrong current with an equal new one is still the wrong-password answer, not "same" (the equality check is not an oracle)
        Assert.Equal(HttpStatusCode.Forbidden, (await Change(client, "the wrong one here", "the wrong one here")).StatusCode);
        _ = refresh;
    }

    [Theory]
    [InlineData("short")]
    [InlineData("12345678901")]
    [InlineData("tab\there is not allowed")]
    [InlineData(null)]
    public async Task The_new_password_follows_the_admin_rules(string? replacement)
    {
        using var w = NewWorld();
        var (name, _) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        var r = await Change(client, Password, replacement);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.True((await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors").TryGetProperty("newPassword", out _));
        Assert.Equal(HttpStatusCode.BadRequest, (await Change(client, Password, new string('x', 129))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode);
    }

    [Fact]
    public async Task A_missing_current_password_or_a_broken_body_is_a_400()
    {
        using var w = NewWorld();
        var (name, _) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        var r = await Change(client, null, Fresh);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.True((await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors").TryGetProperty("currentPassword", out _));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PutAsync("/v1/me/password", new StringContent("{not json", System.Text.Encoding.UTF8, "application/json"))).StatusCode);
    }

    [Fact]
    public async Task A_token_without_a_session_changes_the_password_and_ends_every_session()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (_, refresh1) = await w.SignIn(name);
        var (_, refresh2) = await w.SignIn(name);
        var sessionless = w.Factory.CreateClient();
        sessionless.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(w.Factory,
            new User(id, name, name + "@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "gatekeeper", []));
        Assert.Equal(HttpStatusCode.NoContent, (await Change(sessionless, Password, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Refresh(refresh1)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Refresh(refresh2)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Fresh)).StatusCode);
        Assert.Contains("kept=none", string.Join('\n', (await w.Audit(id)).Select(x => x.GetRawText())));
    }

    [Fact]
    public async Task A_shared_account_a_disabled_user_and_a_foreign_audience_get_no_self_service()
    {
        using var w = NewWorld();
        var (sharedName, sharedId) = await w.NewUser("shared");
        var shared = w.Factory.CreateClient();
        shared.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(w.Factory,
            new User(sharedId, sharedName, sharedName + "@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, UserKind.Shared), "gatekeeper", []));
        Assert.Equal(HttpStatusCode.Forbidden, (await Change(shared, Password, Fresh)).StatusCode);

        var (name, id) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        Assert.Equal(HttpStatusCode.OK, (await w.Admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Change(client, Password, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "admin set this one" })).StatusCode); // the admin path is unchanged

        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Factory.CreateClient().PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = Fresh })).StatusCode);
    }

    [Fact]
    public async Task An_administrator_changes_their_own_password_too()
    {
        using var w = NewWorld();
        var admin = TestAuth.EnsureAdmin(w.Factory);
        var login = await w.Login(admin.Username, TestAuth.AdminPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var c = w.Factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        Assert.Equal(HttpStatusCode.NoContent, (await Change(c, TestAuth.AdminPassword, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/v1/users?limit=1")).StatusCode);
    }

    [Fact]
    public async Task Attempts_are_throttled_per_user_with_429_before_any_hashing_even_for_the_right_password()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        for (var i = 0; i < Endpoints.PasswordFailuresPerUser; i++)
            Assert.Equal(HttpStatusCode.Forbidden, (await Change(client, $"wrong password {i} here", Fresh)).StatusCode);
        var blocked = await Change(client, Password, Fresh);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(int.Parse(blocked.Headers.GetValues("Retry-After").Single()) > 0);
        Assert.Equal(HttpStatusCode.OK, (await w.Login(name, Password)).StatusCode); // the right password was not applied
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Change(client, "x", Fresh)).StatusCode);

        // Audit: exactly one failure row per refused attempt, none for the 429s, and no second "forbidden" row for the same 403.
        var rows = (await w.Audit(id)).Where(x => x.GetProperty("action").GetString() == "PUT /v1/me/password").ToList();
        Assert.Equal(Endpoints.PasswordFailuresPerUser, rows.Count);
        Assert.All(rows, x => Assert.Equal("failure", x.GetProperty("outcome").GetString()));
        Assert.Equal(Endpoints.PasswordFailuresPerUser, (await w.Audit(id)).Count(x => x.GetProperty("detail").GetString()!.Contains("current-password")));
    }

    [Fact]
    public async Task Attempts_are_throttled_per_address_across_users()
    {
        using var w = NewWorld();
        var users = new List<HttpClient>();
        for (var i = 0; i < 5; i++) users.Add((await w.SignIn((await w.NewUser()).Name)).Client);
        for (var i = 0; i < Endpoints.PasswordFailuresPerAddress; i++)
            Assert.Equal(HttpStatusCode.Forbidden, (await Change(users[i % 5], $"wrong password {i} here", Fresh)).StatusCode);
        // A user that has not failed once is stopped by the address (the test host has one address).
        var fresh = (await w.SignIn((await w.NewUser()).Name)).Client;
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Change(fresh, Password, Fresh)).StatusCode);
    }

    [Fact]
    public async Task Rule_violations_count_per_address_only_so_the_owners_typos_never_lock_them_out()
    {
        using var w = NewWorld();
        var (client, _) = await w.SignIn((await w.NewUser()).Name);
        for (var i = 0; i < Endpoints.PasswordFailuresPerUser + 3; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await Change(client, Password, "short")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Change(client, Password, Fresh)).StatusCode); // the per-user limit was not touched
    }

    [Fact]
    public async Task A_flood_of_rule_violations_is_stopped_by_the_address_limit()
    {
        using var w = NewWorld();
        var (client, _) = await w.SignIn((await w.NewUser()).Name);
        for (var i = 0; i < Endpoints.PasswordFailuresPerAddress; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await Change(client, Password, "short")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Change(client, Password, "short")).StatusCode);
    }

    [Fact]
    public async Task Parallel_guesses_cannot_get_past_the_per_user_limit()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        var results = await Task.WhenAll(Enumerable.Range(0, 30).Select(i => Task.Run(async () => (await Change(client, $"wrong guess number {i} x", Fresh)).StatusCode)));
        Assert.Equal(Endpoints.PasswordFailuresPerUser, results.Count(x => x == HttpStatusCode.Forbidden)); // at most 5 verifications per window
        Assert.Equal(30 - Endpoints.PasswordFailuresPerUser, results.Count(x => x == HttpStatusCode.TooManyRequests));
        Assert.Equal(Endpoints.PasswordFailuresPerUser, (await w.Audit(id)).Count(x => x.GetProperty("action").GetString() == "PUT /v1/me/password"));
    }

    [Fact]
    public async Task A_token_of_a_deleted_user_gets_the_uniform_403()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/v1/me")).StatusCode); // warms the access check
        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.DeleteAsync($"/v1/users/{id}")).StatusCode);
        var r = await Change(client, Password, Fresh);
        Assert.Equal($"403|{Endpoints.WrongCurrentPasswordCode}|{Endpoints.WrongCurrentPasswordText}", await Problem(r));
    }

    [Fact]
    public async Task Evicting_by_user_drops_every_cached_access_answer_of_that_user()
    {
        using var w = NewWorld();
        var (name, id) = await w.NewUser();
        var sessions = new List<Guid>();
        for (var i = 0; i < 3; i++)
        {
            var (c, _) = await w.SignIn(name);
            Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/v1/me")).StatusCode);
        }
        var access = w.Factory.Services.GetRequiredService<AdminAccessCheck>();
        var sessionRepo = w.Factory.Services.GetRequiredService<Gatekeeper.Application.ISessionRepository>();
        foreach (var s in await sessionRepo.ListActiveByUserAsync(id, DateTimeOffset.UtcNow))
        {
            Assert.NotNull(await access.StateAsync(id, s.Id, default));
            sessions.Add(s.Id);
        }
        Assert.Equal(3, sessions.Count);
        await sessionRepo.RevokeAllForUserAsync(id, DateTimeOffset.UtcNow); // behind the cache's back
        foreach (var s in sessions) Assert.NotNull(await access.StateAsync(id, s, default)); // still cached
        access.Evict(id);
        foreach (var s in sessions) Assert.Null(await access.StateAsync(id, s, default));
    }

    [Fact]
    public async Task A_success_is_audited_with_the_user_as_actor_and_no_password_appears_in_any_row_or_log()
    {
        var log = new CaptureLog();
        using var w = NewWorld(b => b.ConfigureServices(sv => sv.AddSingleton<ILoggerProvider>(log)));
        var (name, id) = await w.NewUser();
        var (client, _) = await w.SignIn(name);
        await w.SignIn(name);
        var wrong = "WRONG-secret-pw-xyz";
        Assert.Equal(HttpStatusCode.Forbidden, (await Change(client, wrong, Fresh)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Change(client, Password, "tiny-SHORT")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Change(client, Password, Fresh)).StatusCode);

        var rows = (await w.Audit(id)).Where(x => x.GetProperty("action").GetString() == "PUT /v1/me/password").ToList();
        Assert.Equal(3, rows.Count);
        var success = Assert.Single(rows, x => x.GetProperty("outcome").GetString() == "success");
        Assert.Equal(id.ToString(), success.GetProperty("actor").GetString());
        Assert.Contains("sessionsRevoked=1", success.GetProperty("detail").GetString());
        var everything = await w.Admin.GetStringAsync("/v1/audit?limit=200") + string.Join('\n', log.Lines);
        foreach (var secret in new[] { Password, Fresh, wrong, "tiny-SHORT" })
            Assert.DoesNotContain(secret, everything);
    }

    [Fact]
    public async Task Neither_password_is_in_a_response_or_in_the_request_objects_text()
    {
        using var w = NewWorld();
        var (client, _) = await w.SignIn((await w.NewUser()).Name);
        foreach (var (current, replacement) in new[] { ("WRONG-secret-pw-xyz", Fresh), (Password, "tiny-SHORT"), (Password, Password), (Password, Fresh) })
        {
            var r = await Change(client, current, replacement);
            var text = await r.Content.ReadAsStringAsync() + r.Headers + r.Content.Headers;
            Assert.DoesNotContain(current, text);
            Assert.DoesNotContain(replacement, text);
        }
        var request = new OwnPasswordRequest("CUR-secret", "NEW-secret");
        Assert.DoesNotContain("secret", request.ToString());
    }

    [Fact]
    public async Task The_route_is_self_service_only_and_documented()
    {
        using var w = NewWorld();
        var doc = JsonDocument.Parse(await w.Factory.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement;
        var op = doc.GetProperty("paths").GetProperty("/v1/me/password").GetProperty("put");
        Assert.Equal("self", op.GetProperty("x-gatekeeper-access").GetString());
        var statuses = op.GetProperty("responses").EnumerateObject().Select(p => p.Name).OrderBy(x => x).ToArray();
        Assert.Equal(["204", "400", "403", "429"], statuses);
        Assert.True(op.TryGetProperty("requestBody", out _));
    }
}
