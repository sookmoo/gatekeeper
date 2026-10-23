using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6d: optimistic concurrency (version in the body, strong ETag, If-Match on PUT/PATCH/DELETE, 412).</summary>
public class Slice6dApiTests
{
    public static IEnumerable<object[]> Cases() =>
        from store in new[] { "mem", "pg" }
        from kind in new[] { "app", "role", "user", "client" }
        select new object[] { store, kind };

    public static IEnumerable<object[]> Stores() => QaEnv.Stores();

    private sealed record Thing(string Kind, string Path, Func<int, object> Put, Func<int, object> Patch, string ChangedField, Func<int, string> ChangedValue);

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<(Thing Thing, HttpResponseMessage Created, JsonElement Body)> Create(QaEnv e, string kind)
    {
        var app = Unique("app");
        switch (kind)
        {
            case "app":
            {
                var r = await e.Admin.PostAsJsonAsync("/v1/applications", new { name = app });
                var b = await r.Content.ReadFromJsonAsync<JsonElement>();
                return (new Thing(kind, $"/v1/applications/{b.GetProperty("id").GetGuid()}", i => new { name = $"{app}-{i}" }, i => new { name = $"{app}-{i}" }, "name", i => $"{app}-{i}"), r, b);
            }
            case "role":
            {
                var appId = await e.App(app);
                var r = await e.Admin.PostAsJsonAsync($"/v1/applications/{appId}/roles", new { name = "reader", description = "d" });
                var b = await r.Content.ReadFromJsonAsync<JsonElement>();
                return (new Thing(kind, $"/v1/roles/{b.GetProperty("id").GetGuid()}", i => new { name = $"reader{i}", description = "d" }, i => new { description = $"d{i}" }, "description", i => $"d{i}"), r, b);
            }
            case "user":
            {
                var name = Unique("usr");
                var r = await e.Admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com" });
                var b = await r.Content.ReadFromJsonAsync<JsonElement>();
                return (new Thing(kind, $"/v1/users/{b.GetProperty("id").GetGuid()}", i => new { username = name, email = $"{name}@example.com", displayName = $"n{i}" }, i => new { displayName = $"n{i}" }, "displayName", i => $"n{i}"), r, b);
            }
            default:
            {
                var appId = await e.App(app);
                var name = Unique("cli");
                var r = await e.Admin.PostAsJsonAsync("/v1/clients", new { name, application = appId });
                var b = await r.Content.ReadFromJsonAsync<JsonElement>();
                return (new Thing(kind, $"/v1/clients/{b.GetProperty("id").GetGuid()}", i => new { name = $"{name}-{i}" }, i => new { name = $"{name}-{i}" }, "name", i => $"{name}-{i}"), r, b);
            }
        }
    }

    private static Task<HttpResponseMessage> Send(QaEnv e, HttpMethod method, string url, object? body = null, string? ifMatch = null)
    {
        var req = new HttpRequestMessage(method, url);
        if (body is not null) req.Content = JsonContent.Create(body);
        if (ifMatch is not null) req.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        return e.Admin.SendAsync(req);
    }

    private static string? ETag(HttpResponseMessage r) => r.Headers.TryGetValues("ETag", out var v) ? v.Single() : null;

    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    private static async Task<(string? ETag, JsonElement Body)> Get(QaEnv e, Thing t)
    {
        var r = await e.Admin.GetAsync(t.Path);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (ETag(r), await Json(r));
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task Create_get_and_list_carry_version_one_and_a_strong_etag(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, created, body) = await Create(e, kind);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal("\"1\"", ETag(created));
        Assert.Equal(1, body.GetProperty("version").GetInt64());

        var (etag, got) = await Get(e, t);
        Assert.Equal("\"1\"", etag);
        Assert.Equal(1, got.GetProperty("version").GetInt64());
        Assert.False(etag!.StartsWith("W/"));

        var listUrl = kind switch { "app" => "/v1/applications", "user" => "/v1/users", "client" => "/v1/clients", _ => $"/v1/applications/{got.GetProperty("appId").GetGuid()}/roles" };
        var list = await e.Admin.GetAsync(listUrl);
        Assert.Null(ETag(list)); // a list has no single version
        var items = (await Json(list)).GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(body.GetProperty("id").GetGuid(), items.Select(x => x.GetProperty("id").GetGuid()));
        Assert.All(items, x => Assert.True(x.GetProperty("version").GetInt64() >= 1));
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task A_current_etag_succeeds_and_the_answer_carries_the_next_one(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);

        var put = await Send(e, HttpMethod.Put, t.Path, t.Put(1), "\"1\"");
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        Assert.Equal("\"2\"", ETag(put));
        Assert.Equal(2, (await Json(put)).GetProperty("version").GetInt64());

        // the etag of the answer is what the next write needs
        var patch = await Send(e, HttpMethod.Patch, t.Path, t.Patch(2), ETag(put));
        Assert.Equal(HttpStatusCode.OK, patch.StatusCode);
        Assert.Equal("\"3\"", ETag(patch));
        var (etag, body) = await Get(e, t);
        Assert.Equal("\"3\"", etag);
        Assert.Equal(t.ChangedValue(2), body.GetProperty(t.ChangedField).GetString());

        // a list of tags matches when one of them is current
        var multi = await Send(e, HttpMethod.Patch, t.Path, t.Patch(3), "\"9\", \"3\" , \"xy\"");
        Assert.Equal(HttpStatusCode.OK, multi.StatusCode);
        Assert.Equal("\"4\"", ETag(multi));
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task A_stale_etag_is_412_with_a_fixed_problem_and_changes_nothing(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(1), "\"1\"")).StatusCode); // now version 2
        var (before, bodyBefore) = await Get(e, t);

        foreach (var (method, body) in new[] { (HttpMethod.Put, t.Put(5)), (HttpMethod.Patch, t.Patch(5)) })
            foreach (var stale in new[] { "\"1\"", "\"3\"" })
            {
                var r = await Send(e, method, t.Path, body, stale);
                Assert.Equal(HttpStatusCode.PreconditionFailed, r.StatusCode);
                Assert.Equal("application/problem+json", r.Content.Headers.ContentType?.MediaType);
                var problem = await Json(r);
                Assert.Equal(412, problem.GetProperty("status").GetInt32());
                Assert.Equal("The resource was changed by someone else. Fetch it again and retry.", problem.GetProperty("detail").GetString());
                Assert.Null(ETag(r));
            }
        var (after, bodyAfter) = await Get(e, t);
        Assert.Equal(before, after);
        Assert.Equal(bodyBefore.GetRawText(), bodyAfter.GetRawText());

        // the refusals are in the audit trail as failures
        var route = kind switch { "app" => "/v1/applications/{id}", "role" => "/v1/roles/{id}", "user" => "/v1/users/{id}", _ => "/v1/clients/{id}" };
        var rows = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?action={Uri.EscapeDataString("PATCH " + route)}&limit=200")).GetProperty("items").EnumerateArray()
            .Where(x => x.GetProperty("target").GetString()!.Contains(t.Path[(t.Path.LastIndexOf('/') + 1)..])).ToList();
        var failures = rows.Where(x => x.GetProperty("outcome").GetString() == "failure").ToList();
        Assert.Equal(2, failures.Count);
        Assert.All(failures, x => Assert.Contains("PreconditionFailedException", x.GetProperty("detail").GetString()));
        Assert.Single(rows, x => x.GetProperty("outcome").GetString() == "success");
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task A_malformed_if_match_is_400_and_changes_nothing(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        // (an empty header value is dropped by HttpClient itself; PreconditionTests covers the empty string)
        var bad = new[] { "1", "abc", "\"1", "1\"", "W/", "W/1", "\"1\" \"2\"", "*, \"1\"", "\"1\", *", "**", "\"a\"b\"", "'1'", "\"1\"\n", new string('x', 2000), "\"" + new string('1', 2000) + "\"" };
        foreach (var header in bad)
        {
            foreach (var (method, body) in new[] { (HttpMethod.Put, t.Put(7)), (HttpMethod.Patch, t.Patch(7)), (HttpMethod.Delete, (object?)null) })
            {
                HttpResponseMessage r;
                try { r = await Send(e, method, t.Path, body, header); }
                catch (FormatException) { continue; } // the client refuses to send an invalid header at all
                Assert.True(r.StatusCode == HttpStatusCode.BadRequest, $"{method} If-Match [{header}] -> {(int)r.StatusCode}");
                Assert.Contains("If-Match", await r.Content.ReadAsStringAsync());
            }
        }
        var (etag, _) = await Get(e, t);
        Assert.Equal("\"1\"", etag);
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task Star_matches_any_existing_row_and_a_weak_etag_never_matches(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(1), "\"1\"")).StatusCode); // version 2

        foreach (var weak in new[] { "W/\"2\"", "W/\"2\", W/\"1\"" })
            Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(9), weak)).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Delete, t.Path, null, "W/\"2\"")).StatusCode);
        // a weak tag next to a strong current one: the strong one matches
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(2), "W/\"9\", \"2\"")).StatusCode);

        var star = await Send(e, HttpMethod.Put, t.Path, t.Put(3), "*");
        Assert.Equal(HttpStatusCode.OK, star.StatusCode);
        Assert.Equal("\"4\"", ETag(star));
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(4), " * ")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Send(e, HttpMethod.Delete, t.Path, null, "*")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Send(e, HttpMethod.Delete, t.Path, null, "*")).StatusCode); // * needs an existing row
        Assert.Equal(HttpStatusCode.NotFound, (await Send(e, HttpMethod.Put, t.Path, t.Put(5), "*")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task Delete_with_a_stale_etag_is_412_and_with_the_current_one_204(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(1))).StatusCode); // unconditional: version 2

        var stale = await Send(e, HttpMethod.Delete, t.Path, null, "\"1\"");
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync(t.Path)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Send(e, HttpMethod.Delete, t.Path, null, "\"2\"")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync(t.Path)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task Without_if_match_a_write_is_unconditional_and_still_bumps_the_version(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        Assert.Equal("\"2\"", ETag(await Send(e, HttpMethod.Put, t.Path, t.Put(1))));
        Assert.Equal("\"3\"", ETag(await Send(e, HttpMethod.Patch, t.Path, t.Patch(2))));
        Assert.Equal("\"3\"", (await Get(e, t)).ETag);
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task Parallel_requests_with_the_same_etag_let_exactly_one_win(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        foreach (var method in new[] { HttpMethod.Patch, HttpMethod.Put })
        {
            var (etag, _) = await Get(e, t);
            var round = method == HttpMethod.Patch ? 10 : 20;
            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(i =>
                Send(e, method, t.Path, method == HttpMethod.Patch ? t.Patch(round + i) : t.Put(round + i), etag)));
            var codes = results.Select(r => r.StatusCode).ToList();
            Assert.Equal(1, codes.Count(c => c == HttpStatusCode.OK));
            Assert.Equal(7, codes.Count(c => c == HttpStatusCode.PreconditionFailed));
            var (next, body) = await Get(e, t);
            Assert.NotEqual(etag, next);
            // exactly the winner's value is stored
            var winner = results.Single(r => r.StatusCode == HttpStatusCode.OK);
            Assert.Equal(next, ETag(winner));
            Assert.Equal((await Json(winner)).GetProperty(t.ChangedField).GetString(), body.GetProperty(t.ChangedField).GetString());
        }
        // and with a delete racing a patch on the same etag
        var (current, _) = await Get(e, t);
        var race = await Task.WhenAll(Send(e, HttpMethod.Patch, t.Path, t.Patch(99), current), Send(e, HttpMethod.Delete, t.Path, null, current));
        Assert.Equal(1, race.Count(r => r.IsSuccessStatusCode));
        Assert.Equal(1, race.Count(r => r.StatusCode == HttpStatusCode.PreconditionFailed || r.StatusCode == HttpStatusCode.NotFound));
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task A_patch_that_changes_nothing_keeps_the_version_and_returns_the_current_etag(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, t.Path, t.Patch(1))).StatusCode); // version 2
        foreach (var body in new object[] { new { }, t.Patch(1) }) // empty, and the values it already has
        {
            var r = await Send(e, HttpMethod.Patch, t.Path, body, "\"2\"");
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Equal("\"2\"", ETag(r));
        }
        Assert.Equal("\"2\"", (await Get(e, t)).ETag);
        // the precondition is still checked first
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Patch, t.Path, new { }, "\"1\"")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_patch_of_a_role_in_the_reserved_application_is_409_even_when_it_changes_nothing(string store)
    {
        using var e = new QaEnv(store);
        var apps = (await e.Admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray();
        var reserved = apps.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var role = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{reserved}/roles")).GetProperty("items")[0];
        var path = $"/v1/roles/{role.GetProperty("id").GetGuid()}";
        var current = $"\"{role.GetProperty("version").GetInt64()}\"";
        foreach (var body in new object[] { new { }, new { name = role.GetProperty("name").GetString() } })
        {
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Patch, path, body)).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Patch, path, body, current)).StatusCode);
            Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Patch, path, body, "\"999\"")).StatusCode);
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Role_assignments_passwords_secrets_and_sessions_do_not_change_a_version(string store)
    {
        using var e = new QaEnv(store);
        var app = Unique("app");
        var appId = await e.App(app);
        var roleId = await e.Role(appId, "member");
        var userId = await e.User(Unique("usr"), password: null);
        var clientId = await e.Create("/v1/clients", new { name = Unique("cli"), application = appId });

        async Task<string?> Tag(string url) => ETag(await e.Admin.GetAsync(url));
        var before = new[] { await Tag($"/v1/users/{userId}"), await Tag($"/v1/clients/{clientId}"), await Tag($"/v1/roles/{roleId}"), await Tag($"/v1/applications/{appId}") };
        Assert.All(before, t => Assert.Equal("\"1\"", t));

        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password = "correct horse battery" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsync($"/v1/clients/{clientId}/roles/{roleId}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PostAsync($"/v1/clients/{clientId}/secret", null)).StatusCode);
        var name = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}")).GetProperty("username").GetString()!;
        var login = await e.Anon.PostAsJsonAsync("/v1/auth/login", new { username = name, password = "correct horse battery", application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.DeleteAsync($"/v1/users/{userId}/sessions")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/users/{userId}/roles/{roleId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/clients/{clientId}/roles/{roleId}")).StatusCode);

        var after = new[] { await Tag($"/v1/users/{userId}"), await Tag($"/v1/clients/{clientId}"), await Tag($"/v1/roles/{roleId}"), await Tag($"/v1/applications/{appId}") };
        Assert.Equal(before, after);

        // while a change of the row's own fields does
        Assert.Equal("\"2\"", ETag(await Send(e, HttpMethod.Patch, $"/v1/users/{userId}", new { displayName = "x" })));
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task A_missing_resource_is_404_before_a_stale_etag_but_a_malformed_header_is_400_first(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        var missing = t.Path[..(t.Path.LastIndexOf('/') + 1)] + Guid.NewGuid();
        foreach (var header in new[] { "\"41\"", "*", "W/\"1\"" })
            foreach (var (method, body) in new[] { (HttpMethod.Put, t.Put(1)), (HttpMethod.Patch, t.Patch(1)), (HttpMethod.Delete, (object?)null) })
                Assert.Equal(HttpStatusCode.NotFound, (await Send(e, method, missing, body, header)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(e, HttpMethod.Patch, missing, t.Patch(1), "nonsense")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Cases))]
    public async Task With_a_precondition_412_comes_before_validation_and_without_one_validation_is_unchanged(string store, string kind)
    {
        using var e = new QaEnv(store);
        var (t, _, _) = await Create(e, kind);
        // a body that is invalid for every kind: the name/username is empty
        object invalid = kind switch
        {
            "app" => new { name = "" },
            "role" => new { name = "", description = "d" },
            "user" => new { username = "", email = "x@example.com" },
            _ => new { name = "" },
        };
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(e, HttpMethod.Put, t.Path, invalid)).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Put, t.Path, invalid, "\"9\"")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(e, HttpMethod.Put, t.Path, invalid, "\"1\"")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(e, HttpMethod.Put, t.Path, invalid, "*")).StatusCode);
        Assert.Equal("\"1\"", (await Get(e, t)).ETag); // a refused write does not bump
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Reserved_application_and_last_administrator_rules_stay_409_but_come_after_412(string store)
    {
        using var e = new QaEnv(store);
        var apps = (await e.Admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray().ToList();
        var reserved = apps.Single(a => a.GetProperty("name").GetString() == "gatekeeper");
        var path = $"/v1/applications/{reserved.GetProperty("id").GetGuid()}";
        var current = $"\"{reserved.GetProperty("version").GetInt64()}\"";
        foreach (var (method, body) in new[] { (HttpMethod.Put, (object?)new { name = "renamed" }), (HttpMethod.Patch, new { name = "renamed" }), (HttpMethod.Delete, null) })
        {
            Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, method, path, body, "\"999\"")).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, method, path, body, current)).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, method, path, body)).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, method, path, body, "*")).StatusCode);
        }

        // the only administrator cannot be disabled or deleted
        var admin = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users?username={TestAuth.AdminName}")).GetProperty("items")[0];
        var userPath = $"/v1/users/{admin.GetProperty("id").GetGuid()}";
        var tag = $"\"{admin.GetProperty("version").GetInt64()}\"";
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Patch, userPath, new { isActive = false }, "\"999\"")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Patch, userPath, new { isActive = false }, tag)).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Delete, userPath, null, "\"999\"")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Delete, userPath, null, tag)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Delete, userPath, null)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Openapi_describes_version_etag_if_match_and_412(string store)
    {
        using var e = new QaEnv(store);
        var doc = JsonDocument.Parse(await e.Anon.GetStringAsync("/openapi/v1.json")).RootElement;
        var schemas = doc.GetProperty("components").GetProperty("schemas");
        foreach (var name in new[] { "App", "Role", "User", "Client" })
        {
            var s = schemas.GetProperty(name);
            Assert.Equal("integer", s.GetProperty("properties").GetProperty("version").GetProperty("type").GetString());
            Assert.Contains("version", s.GetProperty("required").EnumerateArray().Select(x => x.GetString()));
        }
        var paths = doc.GetProperty("paths");
        foreach (var path in new[] { "/v1/applications/{id}", "/v1/roles/{id}", "/v1/users/{id}", "/v1/clients/{id}" })
            foreach (var op in paths.GetProperty(path).EnumerateObject())
            {
                var method = op.Name;
                var parameters = op.Value.GetProperty("parameters").EnumerateArray().Where(p => p.GetProperty("name").GetString() == "If-Match").ToList();
                var responses = op.Value.GetProperty("responses");
                if (method is "put" or "patch" or "delete")
                {
                    var p = Assert.Single(parameters);
                    Assert.Equal("header", p.GetProperty("in").GetString());
                    Assert.False(p.TryGetProperty("required", out var req) && req.GetBoolean());
                    Assert.True(responses.TryGetProperty("412", out var r412), $"{method} {path}");
                    Assert.Contains("ProblemDetails", r412.GetRawText());
                }
                else
                {
                    Assert.Empty(parameters);
                    Assert.False(responses.TryGetProperty("412", out _), $"{method} {path}");
                }
                if (method is "get" or "put" or "patch")
                    Assert.True(responses.GetProperty("200").GetProperty("headers").TryGetProperty("ETag", out _), $"{method} {path}");
                else
                    Assert.False(responses.TryGetProperty("200", out var ok) && ok.TryGetProperty("headers", out _));
            }
        foreach (var path in new[] { "/v1/applications", "/v1/applications/{id}/roles", "/v1/users", "/v1/clients" })
            Assert.True(paths.GetProperty(path).GetProperty("post").GetProperty("responses").GetProperty("201").GetProperty("headers").TryGetProperty("ETag", out _), path);
    }
}
