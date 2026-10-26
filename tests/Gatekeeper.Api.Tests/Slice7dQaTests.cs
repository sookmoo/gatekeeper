using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>QA for slice 7d, written from the spec (status.md "Slice 7d"): fake clock, no sleeps.</summary>
public class Slice7dQaCoalescerTests
{
    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);

    [Fact]
    public void Counts_are_exact_across_window_boundaries_and_nothing_is_counted_twice()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 5);
        var written = 0;
        var summarised = 0;
        void Hit()
        {
            if (c.Admit("u", "a", "forbidden", out var due)) written++;
            summarised += due.Sum(d => d.Count);
        }
        for (var i = 0; i < 8; i++) Hit();       // 5 written, 3 suppressed
        time.Advance(TimeSpan.FromSeconds(59));
        for (var i = 0; i < 4; i++) Hit();       // still the first window: 4 more suppressed
        time.Advance(TimeSpan.FromSeconds(1));   // exactly one window after the start: ended
        Hit();                                   // summary of 7 + this row opens a window
        Assert.Equal(7, summarised);
        for (var i = 0; i < 9; i++) Hit();       // 4 more written, 5 suppressed
        summarised += c.TakeDue(all: true).Sum(d => d.Count);
        summarised += c.TakeDue(all: true).Sum(d => d.Count); // second flush yields nothing
        Assert.Equal(22, written + summarised);
        Assert.Equal(0, c.TrackedKeys);
    }

    [Fact]
    public void A_key_with_nothing_suppressed_yields_no_summary()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 5);
        for (var i = 0; i < 5; i++) c.Admit("u", "a", "failure", out _);
        time.Advance(Minute);
        Assert.Empty(c.TakeDue());
        Assert.Empty(c.TakeDue(all: true));
    }

    [Fact]
    public void Parallel_admits_add_up_to_written_plus_suppressed()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 5);
        long written = 0, summarised = 0;
        Parallel.For(0, 20_000, i =>
        {
            if (i == 10_000) time.Advance(Minute); // a window boundary in the middle of the flood
            if (c.Admit($"u{i % 3}", "a", "failure", out var due)) Interlocked.Increment(ref written);
            foreach (var d in due) Interlocked.Add(ref summarised, d.Count);
        });
        foreach (var d in c.TakeDue(all: true)) summarised += d.Count;
        Assert.Equal(20_000, written + summarised);
    }

    [Fact]
    public void The_key_cap_holds_under_a_flood_of_distinct_keys_and_loses_no_count_when_room_returns()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 1, maxKeys: 10);
        var written = 0;
        long summarised = 0;
        void Hit(string actor)
        {
            if (c.Admit(actor, "a", "failure", out var due)) written++;
            summarised += due.Sum(d => d.Count);
            Assert.True(c.TrackedKeys <= 10);
        }
        for (var i = 0; i < 100; i++) Hit($"k{i}");
        for (var i = 0; i < 5; i++) Hit("k0"); // tracked: suppressed
        time.Advance(Minute);
        for (var i = 0; i < 100; i++) Hit($"m{i}");
        summarised += c.TakeDue(all: true).Sum(d => d.Count);
        Assert.Equal(205, written + summarised);
    }

    [Fact]
    public void Outcomes_and_actions_are_separate_keys_and_a_summary_is_never_fed_back()
    {
        var time = new FakeTimeProvider();
        var c = new AuditCoalescer(time, freePerWindow: 1);
        foreach (var o in new[] { "failure", "forbidden" })
            foreach (var a in new[] { "x", "y" })
                Assert.True(c.Admit("u", a, o, out _));
        Assert.Equal(4, c.TrackedKeys);
    }
}

public class Slice7dQaApiTests
{
    private const string Password = "correct horse battery";

    private sealed class World : IDisposable
    {
        public FakeTimeProvider Time { get; } = new();
        public AuditCoalescer Coalescer { get; }
        public WebApplicationFactory<Program> Factory { get; }
        public HttpClient Admin { get; }

        public World(int freeRows = 5, int meWrites = 1000, int maxKeys = 10_000)
        {
            Coalescer = new AuditCoalescer(Time, freeRows, maxKeys: maxKeys);
            Factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureServices(s =>
            {
                s.AddSingleton(Coalescer);
                s.AddKeyedSingleton<LoginThrottle>(MeWriteLimitMiddleware.KeyName,
                    (_, _) => new LoginThrottle(Time, maxPerAddress: meWrites, window: TimeSpan.FromMinutes(1)));
            }));
            Admin = Factory.CreateAdminClient();
        }

        public async Task<(HttpClient Client, Guid Id, string Name)> SelfUser()
        {
            var name = $"usr-{Guid.NewGuid():N}"[..20];
            var r = await Admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            return (await LoginAs(name), id, name);
        }

        public async Task<HttpClient> LoginAs(string name, string password = Password)
        {
            var login = await Factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = "gatekeeper", refresh = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var c = Factory.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
            return c;
        }

        public async Task<List<JsonElement>> Audit(Guid actor, string? outcome = null)
        {
            var all = new List<JsonElement>();
            string? cursor = null;
            do
            {
                var page = await Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=200" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"));
                all.AddRange(page.GetProperty("items").EnumerateArray());
                cursor = page.TryGetProperty("nextCursor", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
            } while (cursor is not null);
            return all.Where(r => outcome is null || r.GetProperty("outcome").GetString() == outcome).ToList();
        }

        public static bool IsSummary(JsonElement r) => r.GetProperty("detail").GetString()?.StartsWith("suppressed=") == true;
        public static int Suppressed(JsonElement r) => int.Parse(r.GetProperty("detail").GetString()!.Split(' ')[0]["suppressed=".Length..]);

        /// <summary>Rows written plus counts suppressed for an outcome (after flushing everything pending).</summary>
        public async Task<int> Accounted(Guid actor, string outcome)
        {
            await Factory.Services.GetRequiredService<AuditRecorder>().WriteSummariesAsync(Coalescer.TakeDue(all: true));
            var rows = await Audit(actor, outcome);
            return rows.Count(r => !IsSummary(r)) + rows.Where(IsSummary).Sum(Suppressed);
        }

        public Task FlushAsync(bool all = false) => Factory.Services.GetRequiredService<AuditRecorder>().WriteSummariesAsync(Coalescer.TakeDue(all));

        public void Dispose()
        {
            Admin.Dispose();
            Factory.Dispose();
        }
    }

    private static Task<HttpResponseMessage> Counted(HttpClient c) => c.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}"); // a limited route (404)

    private static StringContent Bad() => new("{not json", Encoding.UTF8, "application/json");

    // ---------------------------------------------------------------- success rows are never coalesced or lost

    [Fact]
    public async Task Successful_idempotent_session_deletes_are_all_audited_with_204()
    {
        using var w = new World(freeRows: 1);
        var (user, id, name) = await w.SelfUser();
        using var second = await w.LoginAs(name);
        var sessions = (await user.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items").EnumerateArray()
            .Where(s => !s.GetProperty("current").GetBoolean()).Select(s => s.GetProperty("id").GetGuid()).ToList();
        var other = Assert.Single(sessions);
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.NoContent, (await user.DeleteAsync($"/v1/me/sessions/{other}")).StatusCode);
        var rows = (await w.Audit(id, "success")).Where(r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions/{id}").ToList();
        Assert.Equal(10, rows.Count);
        Assert.DoesNotContain(await w.Audit(id), World.IsSummary);
    }

    [Fact]
    public async Task Successful_own_password_changes_are_all_audited()
    {
        using var w = new World(freeRows: 1);
        var (user, id, _) = await w.SelfUser();
        var current = Password;
        for (var i = 0; i < 6; i++)
        {
            var next = $"fresh password number {i}";
            var r = await user.PutAsJsonAsync("/v1/me/password", new { currentPassword = current, newPassword = next });
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
            current = next;
        }
        var rows = (await w.Audit(id, "success")).Where(r => r.GetProperty("action").GetString() == "PUT /v1/me/password").ToList();
        Assert.Equal(6, rows.Count);
    }

    [Fact]
    // Changed after the M-2 follow-up: DELETE /v1/me/sessions is counted (limit 7 = 4 refused deletes + 3 of these).
    public async Task An_administrators_self_calls_and_refusals_are_never_coalesced_and_count_toward_the_write_limit()
    {
        using var w = new World(freeRows: 1, meWrites: 7);
        var adminId = TestAuth.EnsureAdmin(w.Factory).Id;
        for (var i = 0; i < 4; i++) Assert.Equal(HttpStatusCode.NotFound, (await Counted(w.Admin)).StatusCode);
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.OK, (await w.Admin.DeleteAsync("/v1/me/sessions")).StatusCode);
        var limited = await Counted(w.Admin);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(limited.Headers.Contains("Retry-After"));
        Assert.Equal(4, (await w.Audit(adminId, "failure")).Count(r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions/{id}"));
        Assert.Equal(3, (await w.Audit(adminId, "success")).Count(r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions"));
        Assert.Equal(0, w.Coalescer.TrackedKeys);
    }

    [Fact]
    public async Task A_demoted_administrator_token_keeps_the_admin_role_claim_so_nothing_is_coalesced()
    {
        using var w = new World(freeRows: 1);
        var (_, id, _) = await w.SelfUser(); // a plain user (no admin role in the store) holding a token that claims the admin role
        var user = (await w.Factory.Services.GetRequiredService<IUserRepository>().GetAsync(id))!;
        using var c = w.Factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(w.Factory, user, Reserved.AdminApp, [Reserved.AdminRole]));
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 8; i++) statuses.Add((await c.GetAsync("/v1/applications")).StatusCode);
        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.Forbidden, s));
        Assert.Equal(8, (await w.Audit(id, "forbidden")).Count);
    }

    // ---------------------------------------------------------------- what is coalesced

    [Fact]
    public async Task Four_xx_failures_of_every_kind_are_coalesced_and_counts_are_exact()
    {
        using var w = new World(freeRows: 2);
        var (user, id, _) = await w.SelfUser();
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.NotFound, (await user.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}")).StatusCode);
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.BadRequest, (await user.PutAsync("/v1/me/password", Bad())).StatusCode);
        for (var i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await user.PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = "x" })).StatusCode);
        // the three PUT variants share one key (same actor, action, outcome): 2 written, the rest counted; the DELETE has its own key
        Assert.Equal(30, await w.Accounted(id, "failure"));
        var rows = await w.Audit(id, "failure");
        Assert.Equal(2, rows.Count(r => !World.IsSummary(r) && r.GetProperty("action").GetString()!.StartsWith("DELETE")));
        Assert.Equal(2, rows.Count(r => !World.IsSummary(r) && r.GetProperty("action").GetString()!.StartsWith("PUT")));
    }

    [Fact]
    public async Task Wrong_current_password_rows_are_bounded_and_accounted_for_and_the_password_throttle_still_answers_429()
    {
        using var w = new World(freeRows: 3);
        var (user, id, _) = await w.SelfUser();
        var seen429 = false;
        var attempts = 0;
        for (var i = 0; i < 40 && !seen429; i++)
        {
            var r = await user.PutAsJsonAsync("/v1/me/password", new { currentPassword = "definitely wrong", newPassword = "another long password" });
            if (r.StatusCode == HttpStatusCode.TooManyRequests)
            {
                seen429 = true;
                Assert.True(r.Headers.Contains("Retry-After"));
            }
            else
            {
                Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
                attempts++;
            }
        }
        Assert.True(seen429, "password throttle did not engage");
        Assert.Equal(attempts, await w.Accounted(id, "failure")); // the 429 wrote nothing, every 403 is written or counted
        // the correct password is refused as long as the throttle holds
        Assert.Equal(HttpStatusCode.TooManyRequests, (await user.PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = "another long password" })).StatusCode);
    }

    [Fact]
    public async Task A_refusal_is_not_hidden_behind_earlier_successes_and_a_success_after_a_flood_is_written()
    {
        using var w = new World(freeRows: 1);
        var (user, id, name) = await w.SelfUser();
        using var second = await w.LoginAs(name);
        for (var i = 0; i < 20; i++) await user.GetAsync("/v1/applications");
        Assert.Equal(HttpStatusCode.OK, (await user.DeleteAsync("/v1/me/sessions")).StatusCode);
        Assert.Equal(1, (await w.Audit(id, "success")).Count(r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions"));
    }

    // ---------------------------------------------------------------- key isolation

    [Fact]
    public async Task Keys_are_isolated_between_users_and_between_actions()
    {
        using var w = new World(freeRows: 3);
        var (a, aId, _) = await w.SelfUser();
        var (b, bId, _) = await w.SelfUser();
        for (var i = 0; i < 20; i++) await a.GetAsync("/v1/applications");
        // user b has not been touched by a's flood
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.Forbidden, (await b.GetAsync("/v1/applications")).StatusCode);
        Assert.Equal(3, (await w.Audit(bId, "forbidden")).Count);
        for (var i = 0; i < 3; i++) await b.GetAsync("/v1/users"); // other action of b, own budget
        Assert.Equal(6, (await w.Audit(bId, "forbidden")).Count);
        Assert.Equal(20, await w.Accounted(aId, "forbidden"));
        Assert.Equal(6, await w.Accounted(bId, "forbidden"));
        Assert.All(await w.Audit(aId, "forbidden"), r => Assert.Equal(aId.ToString(), r.GetProperty("actor").GetString()));
    }

    [Fact]
    public async Task Counts_survive_window_boundaries_sweep_and_host_stop_end_to_end()
    {
        using var w = new World(freeRows: 2);
        var (user, id, _) = await w.SelfUser();
        for (var i = 0; i < 6; i++) await user.GetAsync("/v1/applications");   // 2 + 4
        w.Time.Advance(TimeSpan.FromSeconds(30));
        for (var i = 0; i < 3; i++) await user.GetAsync("/v1/applications");   // same window: 3 more
        w.Time.Advance(TimeSpan.FromSeconds(30));
        await w.FlushAsync();                                                   // sweep: summary of 7
        for (var i = 0; i < 5; i++) await user.GetAsync("/v1/applications");   // new window: 2 + 3
        var flusher = w.Factory.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().OfType<AuditSummaryFlusher>().Single();
        await flusher.StopAsync(CancellationToken.None);
        await flusher.StopAsync(CancellationToken.None); // a second stop must not duplicate the summary
        var rows = await w.Audit(id, "forbidden");
        Assert.Equal(new[] { 3, 7 }, rows.Where(World.IsSummary).Select(World.Suppressed).OrderBy(x => x).ToArray());
        Assert.Equal(14, rows.Count(r => !World.IsSummary(r)) + rows.Where(World.IsSummary).Sum(World.Suppressed));
        Assert.All(rows.Where(World.IsSummary), r =>
        {
            Assert.Equal("GET /v1/applications", r.GetProperty("action").GetString());
            Assert.Matches(@"^suppressed=\d+ since=\d{4}-\d\d-\d\dT", r.GetProperty("detail").GetString()!);
        });
    }

    [Fact]
    public async Task Parallel_floods_account_for_every_request()
    {
        using var w = new World(freeRows: 5);
        var (user, id, _) = await w.SelfUser();
        await Task.WhenAll(Enumerable.Range(0, 20).Select(async _ =>
        {
            for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync("/v1/applications")).StatusCode);
        }));
        Assert.Equal(200, await w.Accounted(id, "forbidden"));
        Assert.Equal(5, (await w.Audit(id, "forbidden")).Count(r => !World.IsSummary(r)));
    }

    [Fact]
    public async Task Parallel_me_writes_never_exceed_the_limit_and_429s_write_nothing()
    {
        using var w = new World(freeRows: 5, meWrites: 10);
        var (user, id, _) = await w.SelfUser();
        var codes = await Task.WhenAll(Enumerable.Range(0, 50).Select(async _ => (await Counted(user)).StatusCode));
        Assert.Equal(10, codes.Count(c => c == HttpStatusCode.NotFound));
        Assert.Equal(40, codes.Count(c => c == HttpStatusCode.TooManyRequests));
        Assert.Equal(10, await w.Accounted(id, "failure"));
    }

    // ---------------------------------------------------------------- rate limit

    [Fact]
    public async Task The_limit_is_a_sliding_window_and_access_returns_when_it_passes()
    {
        using var w = new World(meWrites: 2);
        var (user, id, _) = await w.SelfUser();
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(user)).StatusCode);
        w.Time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(user)).StatusCode);
        var limited = await Counted(user);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        var wait = int.Parse(limited.Headers.GetValues("Retry-After").Single());
        Assert.InRange(wait, 29, 31);
        w.Time.Advance(TimeSpan.FromSeconds(29));
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Counted(user)).StatusCode);
        w.Time.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(user)).StatusCode);
        Assert.Equal(3, await w.Accounted(id, "failure"));
    }

    [Fact]
    public async Task Failed_me_writes_count_toward_the_limit_and_reads_never_do()
    {
        using var w = new World(meWrites: 3);
        var (user, _, _) = await w.SelfUser();
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.NotFound, (await Counted(user)).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Counted(user)).StatusCode);
        for (var i = 0; i < 10; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/v1/me")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/v1/me/sessions")).StatusCode);
        }
    }

    [Fact]
    public async Task Unauthenticated_calls_do_not_spend_a_budget_and_other_paths_are_not_limited_by_this_rule()
    {
        using var w = new World(meWrites: 2);
        var (user, _, _) = await w.SelfUser();
        using var anon = w.Factory.CreateClient();
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.Unauthorized, (await Counted(anon)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(user)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(user)).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Counted(user)).StatusCode);
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.Forbidden, (await user.PostAsJsonAsync("/v1/applications", new { name = "x" })).StatusCode);
    }

    [Fact]
    public async Task Exempt_routes_still_work_with_an_exhausted_budget_but_are_unbounded_audit_writers()
    {
        // FINDING (see report): DELETE /v1/me/sessions is exempt from the limit and always answers 200, so one self token can write
        // an unbounded number of success rows (the exact flood 7d set out to bound). Expect a bound well below the request count.
        using var w = new World(freeRows: 5, meWrites: 3);
        var (user, id, _) = await w.SelfUser();
        for (var i = 0; i < 4; i++) await Counted(user);
        // After the fix DELETE /v1/me/sessions is counted per session (only the password change is exempt): 429 once the budget is gone.
        for (var i = 0; i < 100; i++) Assert.Contains((await user.DeleteAsync("/v1/me/sessions")).StatusCode, new[] { HttpStatusCode.OK, HttpStatusCode.TooManyRequests });
        var rows = (await w.Audit(id)).Count(r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions");
        Assert.True(rows <= 35, $"{rows} audit rows for 100 calls to the exempt DELETE /v1/me/sessions");
    }

    // ---------------------------------------------------------------- key cap at API level

    [Fact]
    public async Task With_a_full_key_table_refusals_are_still_written_not_hidden()
    {
        using var w = new World(freeRows: 1, maxKeys: 2);
        var (a, aId, _) = await w.SelfUser();
        var (b, bId, _) = await w.SelfUser();
        var (c, cId, _) = await w.SelfUser();
        for (var i = 0; i < 3; i++) { await a.GetAsync("/v1/applications"); await b.GetAsync("/v1/applications"); }
        for (var i = 0; i < 4; i++) await c.GetAsync("/v1/applications"); // table full of live windows: c is not tracked
        Assert.Equal(4, (await w.Audit(cId, "forbidden")).Count);
        Assert.Equal(3, await w.Accounted(aId, "forbidden"));
        Assert.Equal(3, await w.Accounted(bId, "forbidden"));
    }

    // ---------------------------------------------------------------- gaps probing the "spec only" boundary

    [Fact]
    public async Task Unmatched_paths_from_a_self_token_do_not_become_unbounded_audit_rows()
    {
        // Every distinct unmatched path is a distinct audit action (the raw path), hence a distinct coalescer key.
        using var w = new World(freeRows: 2);
        var (user, id, _) = await w.SelfUser();
        var statuses = new HashSet<HttpStatusCode>();
        for (var i = 0; i < 40; i++) statuses.Add((await user.PostAsJsonAsync($"/v1/nonexistent-{i}", new { })).StatusCode);
        var rows = await w.Audit(id);
        Assert.True(rows.Count <= 10, $"statuses {string.Join(",", statuses)}: {rows.Count} audit rows for 40 requests to distinct unmatched paths");
    }

    [Fact]
    public async Task Non_guid_session_ids_are_bounded_too()
    {
        using var w = new World(freeRows: 2);
        var (user, id, _) = await w.SelfUser();
        for (var i = 0; i < 40; i++) await user.DeleteAsync($"/v1/me/sessions/not-a-guid-{i}");
        var rows = await w.Audit(id);
        Assert.True(rows.Count <= 10, $"{rows.Count} audit rows for 40 requests to distinct non-guid session ids");
    }

    // ---------------------------------------------------------------- config validation

    [Theory]
    [InlineData("Audit:MeWritesPerMinute", "0")]
    [InlineData("Audit:MeWritesPerMinute", "10001")]
    [InlineData("Audit:MeWritesPerMinute", "-1")]
    [InlineData("Audit:FailureRowsPerMinute", "0")]
    [InlineData("Audit:FailureRowsPerMinute", "1001")]
    public void Out_of_range_settings_stop_the_start(string key, string value)
    {
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseSetting(key, value));
        Assert.ThrowsAny<Exception>(() => f.CreateClient());
    }

    [Theory]
    [InlineData("Audit:MeWritesPerMinute", "1")]
    [InlineData("Audit:MeWritesPerMinute", "10000")]
    [InlineData("Audit:FailureRowsPerMinute", "1")]
    [InlineData("Audit:FailureRowsPerMinute", "1000")]
    public async Task Boundary_settings_start(string key, string value)
    {
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseSetting(key, value));
        using var c = f.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/health")).StatusCode);
    }

    [Fact]
    public async Task The_setting_changes_the_limit()
    {
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseSetting("Audit:MeWritesPerMinute", "2"));
        using var admin = f.CreateAdminClient();
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(admin)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Counted(admin)).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Counted(admin)).StatusCode);
    }

    // ---------------------------------------------------------------- openapi

    [Fact]
    public async Task Openapi_documents_429_on_the_me_writes_and_matches_the_committed_file()
    {
        using var f = new WebApplicationFactory<Program>();
        using var c = f.CreateClient();
        var served = JsonDocument.Parse(await c.GetStringAsync("/openapi/v1.json")).RootElement;
        foreach (var (path, method) in new[] { ("/v1/me/sessions", "delete"), ("/v1/me/sessions/{id}", "delete"), ("/v1/me/password", "put") })
            Assert.True(served.GetProperty("paths").GetProperty(path).GetProperty(method).GetProperty("responses").TryGetProperty("429", out _), $"{method} {path}");
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "Gatekeeper.slnx"))) d = d.Parent;
        var file = JsonDocument.Parse(File.ReadAllText(Path.Combine(d!.FullName, "docs", "openapi.json"))).RootElement;
        Assert.Equal(Canon(file), Canon(served));
        Assert.True(served.GetProperty("paths").GetProperty("/v1/me/sessions").GetProperty("delete").GetProperty("responses").GetProperty("200")
            .GetProperty("content").EnumerateObject().Any());
    }

    private static string Canon(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", e.EnumerateObject().Where(p => p.Name != "servers").OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => $"\"{p.Name}\":{Canon(p.Value)}")) + "}",
        JsonValueKind.Array => "[" + string.Join(",", e.EnumerateArray().Select(Canon)) + "]",
        _ => e.GetRawText(),
    };
}
