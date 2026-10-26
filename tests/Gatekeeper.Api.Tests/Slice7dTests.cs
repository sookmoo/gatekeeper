using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Api.Tests;

public class Slice7dCoalescerTests
{
    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);

    [Fact]
    public void First_rows_pass_the_rest_are_counted_and_the_summary_comes_with_the_next_window()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 5);
        var written = 0;
        for (var i = 0; i < 100; i++) if (c.Admit("u", "GET /v1/x", "forbidden", out var due)) { written++; Assert.Empty(due); }
        Assert.Equal(5, written);
        Assert.Empty(c.TakeDue()); // window still running
        time.Advance(Minute);
        Assert.True(c.Admit("u", "GET /v1/x", "forbidden", out var summaries));
        var s = Assert.Single(summaries);
        Assert.Equal(("u", "GET /v1/x", "forbidden", 95), (s.Actor, s.Action, s.Outcome, s.Count));
        Assert.StartsWith("suppressed=95 since=", s.Detail);
        Assert.Empty(c.TakeDue()); // handed out once
    }

    [Fact]
    public void Keys_are_independent_per_actor_action_and_outcome()
    {
        var c = new AuditCoalescer(new FakeTimeProvider(), freePerWindow: 1);
        Assert.True(c.Admit("a", "x", "failure", out _));
        Assert.False(c.Admit("a", "x", "failure", out _));
        Assert.True(c.Admit("b", "x", "failure", out _));
        Assert.True(c.Admit("a", "y", "failure", out _));
        Assert.True(c.Admit("a", "x", "forbidden", out _));
    }

    [Fact]
    public void A_sweep_yields_ended_windows_and_forgets_them_and_shutdown_yields_the_running_ones()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 1);
        for (var i = 0; i < 4; i++) c.Admit("a", "x", "failure", out _);
        c.Admit("b", "x", "failure", out _);
        time.Advance(Minute);
        var due = c.TakeDue();
        Assert.Equal(3, Assert.Single(due).Count);
        Assert.Equal(0, c.TrackedKeys);

        for (var i = 0; i < 3; i++) c.Admit("a", "x", "failure", out _);
        Assert.Empty(c.TakeDue());
        Assert.Equal(2, Assert.Single(c.TakeDue(all: true)).Count);
    }

    [Fact]
    public void Memory_is_bounded_and_a_full_table_writes_rows_instead_of_hiding_them()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 1, maxKeys: 50);
        for (var i = 0; i < 50; i++) Assert.True(c.Admit($"u{i}", "x", "failure", out _));
        Assert.Equal(50, c.TrackedKeys);
        for (var i = 50; i < 500; i++) Assert.True(c.Admit($"u{i}", "x", "failure", out _)); // not tracked, but written
        Assert.Equal(50, c.TrackedKeys);
        Assert.False(c.Admit("u0", "x", "failure", out _)); // tracked keys still coalesce
        time.Advance(Minute);
        Assert.True(c.Admit("new", "x", "failure", out var due)); // room again after the sweep; u0's count is not lost
        Assert.Equal(1, Assert.Single(due).Count);
    }
}

/// <summary>Slice 7d: bounded audit writes from self-service tokens. Every test has its own factory (the limits are per process).</summary>
public class Slice7dApiTests
{
    private const string Password = "correct horse battery";

    private sealed class World : IDisposable
    {
        public FakeTimeProvider Time { get; } = new();
        public AuditCoalescer Coalescer { get; }
        public WebApplicationFactory<Program> Factory { get; }
        public HttpClient Admin { get; }

        public World(int freeRows = 5, int meWrites = 30)
        {
            Coalescer = new AuditCoalescer(Time, freeRows);
            Factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
            {
                s.AddSingleton(Coalescer);
                s.AddKeyedSingleton<LoginThrottle>(MeWriteLimitMiddleware.KeyName,
                    (_, _) => new LoginThrottle(Time, maxPerAddress: meWrites, window: TimeSpan.FromMinutes(1)));
            }));
            Admin = Factory.CreateAdminClient();
        }

        public string LastName { get; private set; } = "";

        public async Task<HttpClient> SignIn(string name)
        {
            var login = await Factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var c = Factory.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
            return c;
        }

        public async Task<(HttpClient Client, Guid Id)> SelfUser()
        {
            var name = $"usr-{Guid.NewGuid():N}"[..20];
            LastName = name;
            var r = await Admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            var login = await Factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var c = Factory.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
            return (c, id);
        }

        public async Task<List<JsonElement>> Audit(Guid actor, string? outcome = null) =>
            (await Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=200")).GetProperty("items").EnumerateArray()
                .Where(r => outcome is null || r.GetProperty("outcome").GetString() == outcome).ToList();

        public Task FlushAsync(bool all = false) =>
            Factory.Services.GetRequiredService<AuditRecorder>().WriteSummariesAsync(Coalescer.TakeDue(all));

        public void Dispose()
        {
            Admin.Dispose();
            Factory.Dispose();
        }
    }

    [Fact]
    public async Task A_flood_of_403s_gives_the_first_rows_and_one_summary_with_the_count()
    {
        using var w = new World();
        var (user, id) = await w.SelfUser();
        for (var i = 0; i < 100; i++) Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync("/v1/applications")).StatusCode);

        var rows = await w.Audit(id, "forbidden");
        Assert.Equal(5, rows.Count);
        Assert.All(rows, r => Assert.Equal("status 403", r.GetProperty("detail").GetString()));

        w.Time.Advance(TimeSpan.FromMinutes(1));
        await w.FlushAsync(); // what the once-a-minute sweep does
        rows = await w.Audit(id, "forbidden");
        Assert.Equal(6, rows.Count);
        var summary = Assert.Single(rows, r => r.GetProperty("detail").GetString()!.StartsWith("suppressed="));
        Assert.StartsWith("suppressed=95 since=", summary.GetProperty("detail").GetString());
        Assert.Equal("GET /v1/applications", summary.GetProperty("action").GetString());
    }

    [Fact]
    public async Task The_next_refusal_after_the_window_writes_the_summary_and_itself()
    {
        using var w = new World(freeRows: 2);
        var (user, id) = await w.SelfUser();
        for (var i = 0; i < 10; i++) await user.GetAsync("/v1/applications");
        w.Time.Advance(TimeSpan.FromMinutes(2));
        await user.GetAsync("/v1/applications");

        var details = (await w.Audit(id, "forbidden")).Select(r => r.GetProperty("detail").GetString()!).ToList();
        Assert.Equal(4, details.Count);
        Assert.Single(details, d => d.StartsWith("suppressed=8 since="));
    }

    [Fact]
    public async Task A_flood_of_binding_failures_is_coalesced_the_same_way()
    {
        using var w = new World(meWrites: 1000);
        var (user, id) = await w.SelfUser();
        for (var i = 0; i < 100; i++)
        {
            var r = await user.PutAsync("/v1/me/password", new StringContent("{not json", Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }
        Assert.Equal(5, (await w.Audit(id, "failure")).Count);
        w.Time.Advance(TimeSpan.FromMinutes(1));
        await w.FlushAsync();
        var rows = await w.Audit(id, "failure");
        Assert.Equal(6, rows.Count);
        Assert.Contains(rows, r => r.GetProperty("detail").GetString()!.StartsWith("suppressed=95 since="));
    }

    [Fact]
    public async Task Successes_of_state_changes_are_never_coalesced()
    {
        using var w = new World(freeRows: 1);
        var (user, id) = await w.SelfUser();
        for (var i = 0; i < 12; i++) Assert.Equal(HttpStatusCode.OK, (await user.DeleteAsync("/v1/me/sessions")).StatusCode);
        Assert.Equal(12, (await w.Audit(id, "success")).Count(r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions"));
        await w.FlushAsync(all: true);
        Assert.DoesNotContain(await w.Audit(id), r => r.GetProperty("detail").GetString()?.StartsWith("suppressed=") == true);
    }

    [Fact]
    public async Task Administrators_rows_are_never_coalesced()
    {
        using var w = new World(freeRows: 1);
        for (var i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.NotFound, (await w.Admin.PutAsJsonAsync($"/v1/applications/{Guid.NewGuid()}", new { name = "x" })).StatusCode);
        var adminId = TestAuth.EnsureAdmin(w.Factory).Id;
        Assert.Equal(10, (await w.Audit(adminId, "failure")).Count(r => r.GetProperty("action").GetString() == "PUT /v1/applications/{id}"));
        Assert.Equal(0, w.Coalescer.TrackedKeys);
    }

    [Fact]
    public async Task Over_the_write_limit_the_call_is_429_with_retry_after_and_writes_no_row()
    {
        using var w = new World(meWrites: 3);
        var (user, id) = await w.SelfUser();
        var (other, otherId) = await w.SelfUser();
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.NotFound, (await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        var before = (await w.Audit(id)).Count;

        var r = await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.TooManyRequests, r.StatusCode);
        Assert.InRange(int.Parse(r.Headers.GetValues("Retry-After").Single()), 1, 60);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(before, (await w.Audit(id)).Count);

        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/v1/me")).StatusCode); // reads are not limited
        Assert.Equal(HttpStatusCode.NotFound, (await other.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode); // per session

        w.Time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(HttpStatusCode.NotFound, (await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(before + 1, (await w.Audit(id)).Count);
    }

    [Fact]
    public async Task The_default_limit_is_30_a_minute()
    {
        using var f = new WebApplicationFactory<Program>();
        using var admin = f.CreateAdminClient();
        var name = $"usr-{Guid.NewGuid():N}"[..20];
        var created = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password });
        var login = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var user = f.CreateClient();
        user.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        for (var i = 0; i < 30; i++) Assert.Equal(HttpStatusCode.NotFound, (await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task Pending_summaries_are_written_when_the_host_stops()
    {
        using var w = new World(freeRows: 1);
        var (user, id) = await w.SelfUser();
        for (var i = 0; i < 4; i++) await user.GetAsync("/v1/applications");
        var flusher = w.Factory.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().OfType<AuditSummaryFlusher>().Single();
        await flusher.StopAsync(CancellationToken.None);
        Assert.Contains(await w.Audit(id, "forbidden"), r => r.GetProperty("detail").GetString()!.StartsWith("suppressed=3 since="));
    }
}

/// <summary>Slice 7d security review fixes (M-1, M-2, I-1) and the coalescer's retry and sweep rate.</summary>
public class Slice7dReviewTests
{
    private const string Password = "correct horse battery";

    private static WebApplicationFactory<Program> NewFactory(FakeTimeProvider time, AuditCoalescer coalescer, int meWrites = 30) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            s.AddSingleton(coalescer);
            s.AddKeyedSingleton<LoginThrottle>(MeWriteLimitMiddleware.KeyName, (_, _) => new LoginThrottle(time, maxPerAddress: meWrites, window: TimeSpan.FromMinutes(1)));
        }));

    private static async Task<(string Name, Guid Id)> NewUser(HttpClient admin)
    {
        var name = $"usr-{Guid.NewGuid():N}"[..20];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private static async Task<HttpClient> SignIn(WebApplicationFactory<Program> f, string name)
    {
        var login = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var c = f.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    [Fact]
    public async Task A_malformed_flood_does_not_hide_a_wrong_current_password_row()
    {
        var time = new FakeTimeProvider();
        using var f = NewFactory(time, new AuditCoalescer(time, 5));
        using var admin = f.CreateAdminClient();
        var (name, id) = await NewUser(admin);
        using var user = await SignIn(f, name);
        for (var i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await user.PutAsync("/v1/me/password", new StringContent("{not json", Encoding.UTF8, "application/json"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await user.PutAsJsonAsync("/v1/me/password", new { currentPassword = "not the password", newPassword = "tr0ub4dor staple 99" })).StatusCode);
        var rows = (await admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={id}&limit=200")).GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(rows, r => r.GetProperty("detail").GetString()!.Contains("reason=current-password"));
        Assert.Equal(5, rows.Count(r => r.GetProperty("outcome").GetString() == "failure" && !r.GetProperty("detail").GetString()!.Contains("reason=")));
    }

    [Fact]
    public async Task One_session_using_up_its_budget_cannot_stop_the_owner_from_ending_it_from_another_session_or_changing_the_password()
    {
        var time = new FakeTimeProvider();
        using var f = NewFactory(time, new AuditCoalescer(time, 5), meWrites: 30);
        using var admin = f.CreateAdminClient();
        var (name, _) = await NewUser(admin);
        using var attacker = await SignIn(f, name);
        using var victim = await SignIn(f, name);
        var attackerSid = (await attacker.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items").EnumerateArray()
            .Single(s => s.GetProperty("current").GetBoolean()).GetProperty("id").GetGuid();

        for (var i = 0; i < 30; i++) Assert.Equal(HttpStatusCode.NotFound, (await attacker.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await attacker.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await victim.DeleteAsync($"/v1/me/sessions/{attackerSid}")).StatusCode); // the victim's budget is its own
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.GetAsync("/v1/me")).StatusCode);

        // The password change is not counted, so it works for a session whose budget is gone.
        using var second = await SignIn(f, name);
        for (var i = 0; i < 31; i++) await second.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.TooManyRequests, (await second.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await second.DeleteAsync("/v1/me/sessions")).StatusCode); // counted too: its success rows are bounded
        Assert.Equal(HttpStatusCode.NoContent, (await second.PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = "tr0ub4dor staple 99" })).StatusCode);
    }

    [Fact]
    public void Every_me_write_route_and_its_possible_statuses_are_known()
    {
        // Guards I-1: coalescing treats a final 4xx as "changed nothing". A new /v1/me write route, or a new status on one, must be looked at here.
        using var f = new WebApplicationFactory<Program>();
        var routes = f.Services.GetServices<Microsoft.AspNetCore.Routing.EndpointDataSource>().SelectMany(d => d.Endpoints).OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .Where(e => e.RoutePattern.RawText!.StartsWith("/v1/me"))
            .SelectMany(e => (e.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()?.HttpMethods ?? []).Where(m => m is not ("GET" or "HEAD" or "OPTIONS"))
                .Select(m => (Route: $"{m} {e.RoutePattern.RawText!.TrimEnd('/')}", Statuses: e.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>().Select(p => p.StatusCode).OrderBy(x => x).ToArray())))
            .OrderBy(r => r.Route).ToList();
        Assert.Equal(
        new[]
        {
            // Statuses other than 2xx are all decided before anything is written: 404 no such own session, 429 limit, 400/403 password refusals (the write is the last step).
            ("DELETE /v1/me/sessions", new[] { 200, 429 }),
            ("DELETE /v1/me/sessions/{id:guid}", new[] { 204, 404, 429 }),
            ("PUT /v1/me/password", new[] { 204, 400, 403, 429 }),
        }.Select(r => $"{r.Item1}: {string.Join(',', r.Item2)}").ToList(), routes.Select(r => $"{r.Route}: {string.Join(',', r.Statuses)}").ToList());
    }

    [Fact]
    public void A_summary_that_could_not_be_written_is_retried_once_and_the_full_table_sweeps_at_most_once_a_second()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 1);
        c.Admit("a", "x", "failure", out _);
        c.Admit("a", "x", "failure", out _);
        time.Advance(TimeSpan.FromMinutes(1));
        var s = Assert.Single(c.TakeDue());
        c.Requeue(s);
        var again = Assert.Single(c.TakeDue());
        Assert.Equal(1, again.Attempts);
        c.Requeue(again); // second failure: given up
        Assert.Empty(c.TakeDue());

        var full = new AuditCoalescer(time, freePerWindow: 1, maxKeys: 2);
        full.Admit("a", "x", "failure", out _);
        full.Admit("b", "x", "failure", out _);
        time.Advance(TimeSpan.FromMinutes(2));
        Assert.True(full.Admit("c", "x", "failure", out _)); // sweeps the two ended windows
        Assert.Equal(1, full.TrackedKeys);
        full.Admit("d", "x", "failure", out _);
        Assert.True(full.Admit("e", "x", "failure", out _)); // full again, the sweep is rate limited: written, not tracked
        Assert.Equal(2, full.TrackedKeys);
        time.Advance(TimeSpan.FromMinutes(2));
        Assert.True(full.Admit("f", "x", "failure", out _)); // a second later the sweep may run again
        Assert.Equal(1, full.TrackedKeys);
    }
}
