using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA for slice 6b. Runs on a fresh in-memory store and, when GATEKEEPER_TEST_PG is set, on Postgres.</summary>
public class Slice6bQaTests
{
    private const string Password = "correct horse battery";
    public static IEnumerable<object[]> Stores() => [["memory"], ["postgres"]];

    private sealed class Env : IDisposable
    {
        public WebApplicationFactory<Program> F = null!;
        public HttpClient Admin = null!;
        public PgTestDatabase? Db;
        public string AppName = "";
        public Guid RoleId;

        public static async Task<Env> Create(string store)
        {
            var e = new Env();
            if (store == "postgres")
            {
                e.Db = PgTestDatabase.TryCreate();
                Skip.If(e.Db is null, "GATEKEEPER_TEST_PG is not set.");
                using (var m = new ServiceCollection().AddPostgresStore(e.Db!.MigratorConnection).BuildServiceProvider())
                    PostgresStoreExtensions.MigrateAsync(m).GetAwaiter().GetResult();
                e.Db.GrantAppAccess();
                e.F = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
                {
                    b.UseSetting("Store:Provider", "Postgres");
                    b.UseSetting("Auth:SigningKeyPem", TestKey.Pem);
                    b.UseSetting("ConnectionStrings:Gatekeeper", e.Db.AppConnection);
                });
            }
            else e.F = new WebApplicationFactory<Program>();
            e.Admin = e.F.CreateAdminClient();
            e.AppName = "app-" + Guid.NewGuid().ToString("N")[..10];
            var appId = (await e.Post("/v1/applications", new { name = e.AppName })).GetProperty("id").GetGuid();
            e.RoleId = (await e.Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
            return e;
        }

        public void Dispose() { F.Dispose(); Db?.Dispose(); }

        public async Task<JsonElement> Post(string url, object body)
        {
            var r = await Admin.PostAsJsonAsync(url, body);
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }

        public async Task<(string Name, Guid Id)> User(int logins = 1)
        {
            var name = "u-" + Guid.NewGuid().ToString("N")[..10];
            var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsync($"/v1/users/{id}/roles/{RoleId}", null)).StatusCode);
            for (var i = 0; i < logins; i++) await Login(name);
            return (name, id);
        }

        public async Task<string> Login(string name)
        {
            var r = await F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = AppName, refresh = true });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;
        }

        public Task<HttpResponseMessage> Refresh(string t) => F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = t });

        public async Task<List<Guid>> SessionIds(Guid user) =>
            (await Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions?limit=200")).GetProperty("items").EnumerateArray()
                .Select(i => i.GetProperty("id").GetGuid()).ToList();

        public async Task<JsonElement> Audit(string action) =>
            (await Admin.GetFromJsonAsync<JsonElement>("/v1/audit?limit=200&action=" + Uri.EscapeDataString(action))).GetProperty("items");
    }

    private static async Task<(HttpStatusCode, string, string)> Shape(HttpResponseMessage r, params Guid[] ids)
    {
        var body = await r.Content.ReadAsStringAsync();
        foreach (var i in ids) body = body.Replace(i.ToString(), "ID");
        body = System.Text.RegularExpressions.Regex.Replace(body, "\"traceId\":\"[^\"]*\"", "");
        var headers = string.Join("|", r.Headers.Concat(r.Content.Headers)
            .Where(h => !h.Key.Equals("Date", StringComparison.OrdinalIgnoreCase) && !h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            .OrderBy(h => h.Key).Select(h => h.Key + "=" + string.Join(",", h.Value)));
        return (r.StatusCode, body, headers);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task All_not_found_cases_have_identical_status_body_and_headers_for_delete_and_get(string store)
    {
        using var e = await Env.Create(store);
        var owner = await e.User(); var other = await e.User();
        var sid = (await e.SessionIds(owner.Id)).Single();
        var gone = Guid.NewGuid();
        foreach (var verb in new[] { HttpMethod.Delete, HttpMethod.Get })
        {
            var cases = new[]
            {
                $"/v1/users/{other.Id}/sessions/{sid}",        // someone else's
                $"/v1/users/{other.Id}/sessions/{gone}",       // unknown session
                $"/v1/users/{gone}/sessions/{sid}",            // unknown user
                $"/v1/users/{gone}/sessions/{Guid.NewGuid()}", // both unknown
            };
            var shapes = new List<(HttpStatusCode, string, string)>();
            foreach (var c in cases)
            {
                var url = c;
                var resp = await e.Admin.SendAsync(new HttpRequestMessage(verb, url));
                // normalise ids from the route
                var parts = url.Split('/');
                shapes.Add(await Shape(resp, Guid.Parse(parts[3]), Guid.Parse(parts[5])));
            }
            Assert.All(shapes, s => Assert.Equal(HttpStatusCode.NotFound, s.Item1));
            Assert.True(shapes.Select(s => s.Item2).Distinct().Count() == 1, string.Join("\n", shapes.Select(s => s.Item2)));
            Assert.Single(shapes.Select(s => s.Item3).Distinct());
            Assert.DoesNotContain(owner.Id.ToString(), shapes[0].Item2);
        }
        Assert.Single(await e.SessionIds(owner.Id)); // nothing changed
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Bad_guids_are_404_without_touching_anything(string store)
    {
        using var e = await Env.Create(store);
        var u = await e.User();
        var sid = (await e.SessionIds(u.Id)).Single();
        foreach (var url in new[] { $"/v1/users/{u.Id}/sessions/not-a-guid", $"/v1/users/not-a-guid/sessions/{sid}", $"/v1/users/{u.Id}/sessions/{sid}x",
                                    $"/v1/users/{u.Id}/sessions/0", $"/v1/users/{u.Id}/sessions/{sid}/extra" })
        {
            Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync(url)).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync(url)).StatusCode);
        }
        // Empty GUID is a valid GUID: plain 404
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{Guid.Empty}")).StatusCode);
        Assert.Single(await e.SessionIds(u.Id));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Revoke_is_idempotent_leaves_siblings_and_get_keeps_showing_the_ended_row(string store)
    {
        using var e = await Env.Create(store);
        var u = await e.User();
        var t1 = await e.Login(u.Name); // second session
        var ids = await e.SessionIds(u.Id);
        Assert.Equal(2, ids.Count);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{ids[0]}")).StatusCode);
        var first = await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions/{ids[0]}");
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{ids[0]}")).StatusCode);
        var second = await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions/{ids[0]}");
        Assert.Equal(first.GetProperty("revokedAt").GetRawText(), second.GetProperty("revokedAt").GetRawText()); // timestamp not moved
        Assert.Single(await e.SessionIds(u.Id));
        Assert.Equal(ids[1], (await e.SessionIds(u.Id))[0]);
        // the old route also accepts an already revoked session
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/sessions/{ids[0]}")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Parallel_revokes_all_succeed_and_audit_each_once(string store)
    {
        using var e = await Env.Create(store);
        var u = await e.User();
        var sid = (await e.SessionIds(u.Id)).Single();
        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => e.Admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{sid}")));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.NoContent, r.StatusCode));
        Assert.Empty(await e.SessionIds(u.Id));
        var rows = (await e.Audit("DELETE /v1/users/{id}/sessions/{sessionId}")).EnumerateArray().Count(r => r.ToString().Contains(sid.ToString()));
        Assert.Equal(20, rows);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Audit_rows_cover_success_and_the_404_case_and_the_old_route_note(string store)
    {
        using var e = await Env.Create(store);
        var owner = await e.User(); var other = await e.User();
        var sid = (await e.SessionIds(owner.Id)).Single();
        await e.Admin.DeleteAsync($"/v1/users/{other.Id}/sessions/{sid}");       // 404
        await e.Admin.DeleteAsync($"/v1/users/{owner.Id}/sessions/{sid}");       // 204
        var rows = (await e.Audit("DELETE /v1/users/{id}/sessions/{sessionId}")).EnumerateArray().Select(r => r.ToString()).ToList();
        Assert.True(rows.Any(r => r.Contains($"id={other.Id} sessionId={sid}") && r.Contains("\"outcome\":\"failure\"")), string.Join("\n", rows));
        Assert.Contains(rows, r => r.Contains($"id={owner.Id} sessionId={sid}") && r.Contains("\"outcome\":\"success\""));
        Assert.DoesNotContain(rows, r => r.Contains($"id={other.Id} sessionId={sid}") && r.Contains("\"outcome\":\"success\""));

        var o2 = await e.User(); var s2 = (await e.SessionIds(o2.Id)).Single();
        await e.Admin.DeleteAsync($"/v1/sessions/{s2}");
        await e.Admin.DeleteAsync($"/v1/sessions/{s2}");                 // idempotent, note still has owner
        var missing = Guid.NewGuid();
        await e.Admin.DeleteAsync($"/v1/sessions/{missing}");            // 404
        var old = (await e.Audit("DELETE /v1/sessions/{id}")).EnumerateArray().Select(r => r.ToString()).ToList();
        Assert.Equal(2, old.Count(r => r.Contains($"user={o2.Id}") && r.Contains("status 204")));
        var miss = Assert.Single(old, r => r.Contains(missing.ToString()));
        Assert.Contains("NotFoundException", miss);
        Assert.DoesNotContain("user=", miss);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Revoke_all_is_unaffected_and_counts_only_active_sessions(string store)
    {
        using var e = await Env.Create(store);
        var u = await e.User(3);
        var ids = await e.SessionIds(u.Id);
        await e.Admin.DeleteAsync($"/v1/users/{u.Id}/sessions/{ids[0]}");
        var r = await e.Admin.DeleteAsync($"/v1/users/{u.Id}/sessions");
        var body = await r.Content.ReadAsStringAsync();
        Assert.Contains("\"revoked\":2", body.Replace(" ", ""));
        Assert.Empty(await e.SessionIds(u.Id));
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync($"/v1/users/{Guid.NewGuid()}/sessions")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Scoped_routes_need_an_admin_token(string store)
    {
        using var e = await Env.Create(store);
        var u = await e.User();
        var sid = (await e.SessionIds(u.Id)).Single();
        var anon = e.F.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.DeleteAsync($"/v1/users/{u.Id}/sessions/{sid}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync($"/v1/users/{u.Id}/sessions/{sid}")).StatusCode);
        // a non-admin user's own access token must not reach the route
        var login = await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = u.Name, password = Password, application = e.AppName });
        var tok = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        var c = e.F.CreateClient();
        c.DefaultRequestHeaders.Authorization = new("Bearer", tok);
        Assert.True((await c.DeleteAsync($"/v1/users/{u.Id}/sessions/{sid}")).StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized);
        Assert.Single(await e.SessionIds(u.Id)); // original untouched
    }

    [Fact]
    public async Task Committed_openapi_json_marks_only_the_old_route_deprecated()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "docs", "openapi.json"))) dir = Path.GetDirectoryName(dir);
        Assert.NotNull(dir);
        var committed = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(dir!, "docs", "openapi.json"))).RootElement.GetProperty("paths");
        Assert.True(committed.GetProperty("/v1/sessions/{id}").GetProperty("delete").GetProperty("deprecated").GetBoolean());
        Assert.True(committed.TryGetProperty("/v1/users/{id}/sessions/{sessionId}", out var scoped));
        Assert.True(scoped.TryGetProperty("get", out _) && scoped.TryGetProperty("delete", out _));
        foreach (var path in committed.EnumerateObject())
            foreach (var op in path.Value.EnumerateObject())
                if (op.Value.ValueKind == JsonValueKind.Object && op.Value.TryGetProperty("deprecated", out _))
                    Assert.Equal(("/v1/sessions/{id}", "delete"), (path.Name, op.Name));
        using var f = new WebApplicationFactory<Program>();
        var served = JsonDocument.Parse(await f.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement.GetProperty("paths");
        Assert.Equal(committed.GetProperty("/v1/users/{id}/sessions/{sessionId}").GetRawText().Length > 0, served.TryGetProperty("/v1/users/{id}/sessions/{sessionId}", out _));
    }
}
