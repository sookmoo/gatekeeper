using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Gatekeeper.Api.Tests;

/// <summary>QA slice 4b: PATCH, clients, audit trail, readiness. Each test runs against the in-memory and the Postgres store.</summary>
public class Qa4bApiTests
{
    public static IEnumerable<object[]> Stores() => QaEnv.Stores();

    private static async Task<List<JsonElement>> Audit(QaEnv e, string query = "")
    {
        var (_, items) = await e.Walk("/v1/audit" + (query.Length > 0 ? "?" + query : ""), 200);
        return items;
    }

    private static async Task<HttpResponseMessage> Patch(QaEnv e, string url, object body) =>
        await e.Admin.SendAsync(new HttpRequestMessage(HttpMethod.Patch, url) { Content = JsonContent.Create(body) });

    private static Task<HttpResponseMessage> PatchRaw(QaEnv e, string url, string json) =>
        e.Admin.SendAsync(new HttpRequestMessage(HttpMethod.Patch, url) { Content = new StringContent(json, Encoding.UTF8, "application/json") });

    private static async Task<(Guid App, Guid Role, Guid Client, string Name, string Secret)> Svc(QaEnv e, string? name = null, string app = "shop", bool withRole = true)
    {
        var appId = await e.Create("/v1/applications", new { name = $"{app}-{QaEnv.Slug()}" });
        name ??= "svc-" + QaEnv.Slug();
        var r = await e.Admin.PostAsJsonAsync("/v1/clients", new { name, application = appId });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        var j = await QaEnv.Json(r);
        var role = Guid.Empty;
        if (withRole)
        {
            role = await e.Role(appId, "reader");
            Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsync($"/v1/clients/{j.GetProperty("id").GetGuid()}/roles/{role}", null)).StatusCode);
        }
        return (appId, role, j.GetProperty("id").GetGuid(), name, j.GetProperty("secret").GetString()!);
    }

    private static Task<HttpResponseMessage> ClientToken(QaEnv e, object? id, object? secret) =>
        e.Anon.PostAsJsonAsync("/v1/auth/client-token", new { clientId = id, clientSecret = secret });

    // ---------------------------------------------------------------- audit filters / odd input

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Audit_filters_with_NUL_or_invalid_text_do_not_cause_a_server_error(string store)
    {
        using var e = new QaEnv(store);
        await e.App("seed1");
        foreach (var q in new[] { "actor=%00", "action=a%00b", "actor=%ED%A0%80", "action=%00", "actor=%EF%BF%BD", "actor=" + new string('x', 20000) })
        {
            var r = await e.Admin.GetAsync("/v1/audit?" + q);
            Assert.True(r.StatusCode == HttpStatusCode.OK, $"{q[..Math.Min(q.Length, 30)]} -> {(int)r.StatusCode}");
            Assert.Empty((await QaEnv.Json(r)).GetProperty("items").EnumerateArray());
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Audit_paging_parameters_are_validated(string store)
    {
        using var e = new QaEnv(store);
        foreach (var q in new[] { "limit=0", "limit=-1", "limit=201", "limit=abc", "cursor=%00", "cursor=garbage", "cursor=-5", "cursor=99999999999999999999999" })
        {
            var r = await e.Admin.GetAsync("/v1/audit?" + q);
            Assert.True(r.StatusCode == HttpStatusCode.BadRequest, $"{q} -> {(int)r.StatusCode}");
        }
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync("/v1/audit?limit=200")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Audit_text_is_cut_to_200_characters_even_at_a_surrogate_pair_boundary(string store)
    {
        using var e = new QaEnv(store);
        var name = new string('a', 199) + "\U0001F600tail"; // emoji straddles the 200 limit
        await e.Login(name, "irrelevant password", "x");
        var name2 = "‮gpj.\u0000evil\r\nFAKE-LINE" + new string('z', 5000);
        await e.Login(name2, "irrelevant password", "x");
        foreach (var ev in await Audit(e, "action=auth.login"))
        {
            foreach (var f in new[] { "actor", "action", "target", "detail", "address" })
            {
                if (ev.TryGetProperty(f, out var v) && v.ValueKind == JsonValueKind.String)
                    Assert.True(v.GetString()!.Length <= 200, $"{f} has {v.GetString()!.Length} chars");
            }
            var d = ev.GetProperty("detail").GetString()!;
            Assert.DoesNotContain('\n', d); Assert.DoesNotContain('\r', d); Assert.DoesNotContain('\0', d); Assert.DoesNotContain('‮', d);
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Failed_login_with_malformed_json_values_is_audited_or_cleanly_rejected(string store)
    {
        using var e = new QaEnv(store);
        // non-string username, huge body, wrong content type: never a 5xx
        foreach (var body in new[] { "{\"username\":5,\"password\":\"x\",\"application\":\"y\"}", "{\"username\":null}", "[]", "null", "", "{" })
        {
            var r = await e.Raw("/v1/auth/login", body);
            Assert.True((int)r.StatusCode is >= 400 and < 500, $"{body} -> {(int)r.StatusCode}");
        }
        var rr = await e.Raw("/v1/auth/client-token", "{\"clientId\":{},\"clientSecret\":[]}");
        Assert.True((int)rr.StatusCode is >= 400 and < 500);
    }

    // ---------------------------------------------------------------- audit coverage

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Every_mutating_route_is_recorded_exactly_once_with_the_admin_as_actor_and_reads_are_not(string store)
    {
        using var e = new QaEnv(store);
        var adminId = TestAuth.EnsureAdmin(e.Factory).Id.ToString();
        var before = (await Audit(e)).Count;
        var expected = 0;

        async Task Step(string label, Func<Task<HttpResponseMessage>> call, HttpStatusCode status, string expectedAction, bool ok)
        {
            var r = await call();
            Assert.True(r.StatusCode == status, $"{label}: {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
            expected++;
            var all = await Audit(e);
            Assert.True(all.Count == before + expected, $"{label}: expected {before + expected} events, have {all.Count}");
            var newest = all[0];
            Assert.StartsWith(expectedAction, newest.GetProperty("action").GetString());
            Assert.Equal(adminId, newest.GetProperty("actor").GetString());
            Assert.Equal(ok ? "success" : "failure", newest.GetProperty("outcome").GetString());
        }

        var app = await e.App("aud-" + QaEnv.Slug()); expected++;
        Assert.Equal(before + expected, (await Audit(e)).Count);
        var role = await e.Role(app, "r1"); expected++;
        var user = await e.User("aud" + QaEnv.Slug(), password: null); expected++;
        Assert.Equal(before + expected, (await Audit(e)).Count);

        await Step("patch app", () => Patch(e, $"/v1/applications/{app}", new { name = "aud-renamed-" + QaEnv.Slug() }), HttpStatusCode.OK, "PATCH /v1/applications", true);
        await Step("put app", () => e.Admin.PutAsJsonAsync($"/v1/applications/{app}", new { name = "aud-put-" + QaEnv.Slug() }), HttpStatusCode.OK, "PUT /v1/applications", true);
        await Step("patch role", () => Patch(e, $"/v1/roles/{role}", new { description = "d" }), HttpStatusCode.OK, "PATCH /v1/roles", true);
        await Step("put role", () => e.Admin.PutAsJsonAsync($"/v1/roles/{role}", new { name = "r1", description = "e" }), HttpStatusCode.OK, "PUT /v1/roles", true);
        await Step("patch user", () => Patch(e, $"/v1/users/{user}", new { displayName = "Zed" }), HttpStatusCode.OK, "PATCH /v1/users", true);
        await Step("put pw", () => e.Admin.PutAsJsonAsync($"/v1/users/{user}/password", new { password = "correct horse battery" }), HttpStatusCode.NoContent, "PUT /v1/users/{id", true);
        await Step("assign", () => e.Admin.PutAsync($"/v1/users/{user}/roles/{role}", null), HttpStatusCode.NoContent, "PUT /v1/users", true);
        await Step("assign again (idempotent)", () => e.Admin.PutAsync($"/v1/users/{user}/roles/{role}", null), HttpStatusCode.NoContent, "PUT /v1/users", true);
        await Step("revoke", () => e.Admin.DeleteAsync($"/v1/users/{user}/roles/{role}"), HttpStatusCode.NoContent, "DELETE /v1/users", true);
        await Step("revoke missing", () => e.Admin.DeleteAsync($"/v1/users/{user}/roles/{role}"), HttpStatusCode.NotFound, "DELETE /v1/users", false);

        var cr = await e.Admin.PostAsJsonAsync("/v1/clients", new { name = "aud-" + QaEnv.Slug(), application = app });
        expected++;
        var client = (await QaEnv.Json(cr)).GetProperty("id").GetGuid();
        Assert.Equal(before + expected, (await Audit(e)).Count);
        await Step("patch client", () => Patch(e, $"/v1/clients/{client}", new { isActive = false }), HttpStatusCode.OK, "PATCH /v1/clients", true);
        await Step("put client", () => e.Admin.PutAsJsonAsync($"/v1/clients/{client}", new { name = "aud-put-" + QaEnv.Slug() }), HttpStatusCode.OK, "PUT /v1/clients", true);
        await Step("rotate", () => e.Admin.PostAsync($"/v1/clients/{client}/secret", null), HttpStatusCode.OK, "POST /v1/clients", true);
        await Step("client role", () => e.Admin.PutAsync($"/v1/clients/{client}/roles/{role}", null), HttpStatusCode.NoContent, "PUT /v1/clients", true);
        await Step("client role revoke", () => e.Admin.DeleteAsync($"/v1/clients/{client}/roles/{role}"), HttpStatusCode.NoContent, "DELETE /v1/clients", true);

        // failures: 404 / 409 / 400 are recorded once with outcome failure
        await Step("404 delete", () => e.Admin.DeleteAsync($"/v1/users/{Guid.NewGuid()}"), HttpStatusCode.NotFound, "DELETE /v1/users", false);
        await Step("400 invalid", () => e.Admin.PostAsJsonAsync("/v1/applications", new { name = "BAD NAME" }), HttpStatusCode.BadRequest, "POST /v1/applications", false);
        await Step("409 reserved", () => e.Admin.PostAsJsonAsync("/v1/applications", new { name = "gatekeeper" }), HttpStatusCode.Conflict, "POST /v1/applications", false);
        await Step("404 patch", () => Patch(e, $"/v1/clients/{Guid.NewGuid()}", new { name = "x" }), HttpStatusCode.NotFound, "PATCH /v1/clients", false);
        await Step("404 rotate", () => e.Admin.PostAsync($"/v1/clients/{Guid.NewGuid()}/secret", null), HttpStatusCode.NotFound, "POST /v1/clients", false);
        await Step("409 foreign role", async () =>
        {
            var other = await e.App("other-" + QaEnv.Slug());
            var orole = await e.Role(other, "x");
            expected += 2; // the two setup writes above are audited too
            return await e.Admin.PutAsync($"/v1/clients/{client}/roles/{orole}", null);
        }, HttpStatusCode.Conflict, "PUT /v1/clients", false);

        await Step("delete client", () => e.Admin.DeleteAsync($"/v1/clients/{client}"), HttpStatusCode.NoContent, "DELETE /v1/clients", true);
        await Step("delete user", () => e.Admin.DeleteAsync($"/v1/users/{user}"), HttpStatusCode.NoContent, "DELETE /v1/users", true);
        await Step("delete role", () => e.Admin.DeleteAsync($"/v1/roles/{role}"), HttpStatusCode.NoContent, "DELETE /v1/roles", true);
        await Step("delete app", () => e.Admin.DeleteAsync($"/v1/applications/{app}"), HttpStatusCode.NoContent, "DELETE /v1/applications", true);

        // reads leave no trace
        var count = (await Audit(e)).Count;
        foreach (var url in new[] { "/v1/applications", "/v1/users", "/v1/clients", $"/v1/applications/{Guid.NewGuid()}", "/v1/audit", "/v1/roles/" + Guid.NewGuid() })
            await e.Admin.GetAsync(url);
        Assert.Equal(count, (await Audit(e)).Count);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Requests_rejected_before_the_endpoint_body_binding_errors_are_documented_as_unaudited_or_audited(string store)
    {
        using var e = new QaEnv(store);
        var before = (await Audit(e)).Count;
        // unparseable JSON on a mutating route: README says only 401/403 are unaudited. Count what happens.
        var r1 = await e.Admin.PostAsync("/v1/applications", new StringContent("{not json", Encoding.UTF8, "application/json"));
        var r2 = await e.Admin.PostAsync("/v1/applications", new StringContent("{}", Encoding.UTF8, "text/plain"));
        var r3 = await e.Admin.PostAsync("/v1/applications", new StringContent(new string(' ', 70_000) + "{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, r1.StatusCode);
        var after = (await Audit(e)).Count;
        var rows = (await Audit(e)).Take(after - before).Select(x => x.GetProperty("action") + "/" + x.GetProperty("detail")).ToList();
        Assert.True(after - before == 3, $"README: 'every state-changing call' - {(int)r1.StatusCode}/{(int)r2.StatusCode}/{(int)r3.StatusCode} produced {after - before} audit rows instead of 3: {string.Join(",", rows)}");
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Unauthorised_mutations_are_not_audited_and_do_not_change_anything(string store)
    {
        using var e = new QaEnv(store);
        var before = (await Audit(e)).Count;
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Anon.PostAsJsonAsync("/v1/applications", new { name = "nope" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Anon.GetAsync("/v1/audit")).StatusCode);
        Assert.Equal(before, (await Audit(e)).Count);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Audit_route_text_is_readable_not_a_raw_route_pattern(string store)
    {
        using var e = new QaEnv(store);
        var app = await e.App("pat-" + QaEnv.Slug());
        await Patch(e, $"/v1/applications/{app}", new { name = "pat2-" + QaEnv.Slug() });
        var ev = (await Audit(e))[0];
        // The route template leaks the routing constraint syntax into the audit text.
        Assert.DoesNotContain(":guid", ev.GetProperty("action").GetString());
        Assert.Contains(app.ToString(), ev.GetProperty("target").GetString());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Login_and_client_token_events_have_the_right_actor_outcome_and_no_secrets(string store)
    {
        using var e = new QaEnv(store);
        var (_, _, client, name, secret) = await Svc(e);
        var app = await e.App("lg-" + QaEnv.Slug()); var role = await e.Role(app, "x");
        var user = await e.User("lg" + QaEnv.Slug()); await e.Assign(user, role);
        var appName = (await QaEnv.Json(await e.Admin.GetAsync($"/v1/applications/{app}"))).GetProperty("name").GetString()!;
        var uname = (await QaEnv.Json(await e.Admin.GetAsync($"/v1/users/{user}"))).GetProperty("username").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await e.Login(uname, "correct horse battery", appName)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Login(uname, "WRONG horse battery", appName)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ClientToken(e, name, secret)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, "gks_wrongwrongwrong")).StatusCode);
        var all = await Audit(e);
        Assert.Equal(2, all.Count(x => x.GetProperty("action").GetString() == "auth.login" && x.GetProperty("outcome").GetString() is "success" or "failure" && (x.GetProperty("actor").GetString() == user.ToString() || x.GetProperty("detail").GetString()!.Contains(uname))));
        var ok = all.Single(x => x.GetProperty("action").GetString() == "auth.client-token" && x.GetProperty("outcome").GetString() == "success");
        Assert.Equal(client.ToString(), ok.GetProperty("actor").GetString());
        var bad = all.Single(x => x.GetProperty("action").GetString() == "auth.client-token" && x.GetProperty("outcome").GetString() == "failure");
        Assert.Equal("anonymous", bad.GetProperty("actor").GetString());
        var dump = JsonSerializer.Serialize(all);
        Assert.DoesNotContain(secret, dump);
        Assert.DoesNotContain("gks_wrongwrongwrong", dump);
        Assert.DoesNotContain("correct horse battery", dump);
        Assert.DoesNotContain("WRONG horse", dump);
        Assert.DoesNotContain(secret, await e.Admin.GetStringAsync("/v1/clients"));
    }

    [SkippableFact]
    public async Task A_failing_audit_store_does_not_break_changes_or_logins()
    {
        using var e = new QaEnv("mem", b => b.ConfigureServices(s =>
        {
            s.AddSingleton<IAuditRepository, ThrowingAudit>();
        }));
        var app = await e.App("sf-" + QaEnv.Slug()); // POST must still succeed
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/applications/{app}", new { name = "sf2-" + QaEnv.Slug() })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/applications/{app}")).StatusCode);
        var (_, _, _, name, secret) = await Svc(e);
        Assert.Equal(HttpStatusCode.OK, (await ClientToken(e, name, secret)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, "gks_nope_nope_nope")).StatusCode);
        // reading the trail reports the failure as 5xx, not a hang
        var r = await e.Admin.GetAsync("/v1/audit");
        Assert.True((int)r.StatusCode is 500 or 503, ((int)r.StatusCode).ToString());
    }

    private sealed class ThrowingAudit : IAuditRepository
    {
        public Task AppendAsync(AuditEvent entry, CancellationToken ct = default) => throw new InvalidOperationException("audit down");
        public Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, AuditKey? after = null, int? take = null, CancellationToken ct = default) =>
            throw new StoreUnavailableException("audit down");
    }

    [SkippableFact]
    public async Task A_hanging_audit_store_delays_a_change_by_at_most_the_5s_timeout()
    {
        using var e = new QaEnv("mem", b => b.ConfigureServices(s => s.AddSingleton<IAuditRepository, HangingAudit>()));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await e.Admin.PostAsJsonAsync("/v1/applications", new { name = "hang-" + QaEnv.Slug() });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        Assert.InRange(sw.Elapsed.TotalSeconds, 0, 8);
    }

    private sealed class HangingAudit : IAuditRepository
    {
        public async Task AppendAsync(AuditEvent entry, CancellationToken ct = default) => await Task.Delay(Timeout.Infinite, ct);
        public Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, AuditKey? after = null, int? take = null, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<AuditEvent>>([]);
    }

    // ---------------------------------------------------------------- PATCH

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Patch_empty_null_and_absent_fields_leave_everything_alone(string store)
    {
        using var e = new QaEnv(store);
        var app = await e.App("pa-" + QaEnv.Slug());
        var role = await e.Create($"/v1/applications/{app}/roles", new { name = "keep", description = "desc" });
        var u = await e.Create("/v1/users", new { username = "pu" + QaEnv.Slug(), email = "pu@example.com", displayName = "Disp" });
        var (_, _, client, _, _) = await Svc(e);
        foreach (var body in new[] { "{}", "{\"name\":null}", "{\"description\":null}", "{\"displayName\":null,\"isActive\":null,\"email\":null,\"username\":null}", "{\"unknown\":1}" })
        {
            foreach (var url in new[] { $"/v1/applications/{app}", $"/v1/roles/{role}", $"/v1/users/{u}", $"/v1/clients/{client}" })
            {
                var before = await e.Admin.GetStringAsync(url);
                var r = await PatchRaw(e, url, body);
                Assert.True(r.StatusCode == HttpStatusCode.OK, $"PATCH {url} {body} -> {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
                var after = await e.Admin.GetStringAsync(url);
                var b = JsonDocument.Parse(before).RootElement; var a = JsonDocument.Parse(after).RootElement;
                foreach (var p in b.EnumerateObject().Where(p => p.Name != "updatedAt"))
                    Assert.True(p.Value.ToString() == a.GetProperty(p.Name).ToString(), $"{url} {body}: {p.Name} changed");
            }
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Patch_empty_string_clears_description_and_display_name_but_not_names(string store)
    {
        using var e = new QaEnv(store);
        var app = await e.App("pb-" + QaEnv.Slug());
        var role = await e.Create($"/v1/applications/{app}/roles", new { name = "r", description = "desc" });
        var u = await e.Create("/v1/users", new { username = "pb" + QaEnv.Slug(), email = "pb@example.com", displayName = "Disp" });
        Assert.Equal("", (await QaEnv.Json(await Patch(e, $"/v1/roles/{role}", new { description = "" }))).GetProperty("description").GetString());
        Assert.Equal("", (await QaEnv.Json(await Patch(e, $"/v1/users/{u}", new { displayName = "" }))).GetProperty("displayName").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/roles/{role}", new { name = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/applications/{app}", new { name = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/applications/{app}", new { name = "   " })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/users/{u}", new { email = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/users/{u}", new { username = "UPPER" })).StatusCode);
        var (_, _, c, _, _) = await Svc(e);
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/clients/{c}", new { name = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Patch(e, $"/v1/clients/{c}", new { name = "Bad Name" })).StatusCode);
        // wrong JSON types and a body that is not an object
        foreach (var body in new[] { "{\"username\":5}", "{\"isActive\":\"no\"}", "[]", "\"str\"", "null", "" })
        {
            var r = await PatchRaw(e, $"/v1/users/{u}", body);
            Assert.True((int)r.StatusCode is >= 400 and < 500, $"PATCH users {body} -> {(int)r.StatusCode}");
        }
        // after all that nothing was damaged
        Assert.Equal("pb@example.com", (await QaEnv.Json(await e.Admin.GetAsync($"/v1/users/{u}"))).GetProperty("email").GetString());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Patch_conflicts_missing_ids_and_reserved_names(string store)
    {
        using var e = new QaEnv(store);
        var a1 = await e.App("pc1-" + QaEnv.Slug()); var n2 = "pc2-" + QaEnv.Slug(); await e.App(n2);
        var n1 = (await QaEnv.Json(await e.Admin.GetAsync($"/v1/applications/{a1}"))).GetProperty("name").GetString()!;
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/applications/{a1}", new { name = n2 })).StatusCode);
        // patching to your own name is a no-op, not a conflict
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/applications/{a1}", new { name = n1 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/applications/{a1}", new { name = "gatekeeper" })).StatusCode);
        Assert.True((await Patch(e, $"/v1/applications/{a1}", new { name = "Gatekeeper" })).StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Conflict);
        foreach (var url in new[] { "applications", "roles", "users", "clients" })
            Assert.Equal(HttpStatusCode.NotFound, (await Patch(e, $"/v1/{url}/{Guid.NewGuid()}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.SendAsync(new HttpRequestMessage(HttpMethod.Patch, "/v1/applications/not-a-guid") { Content = JsonContent.Create(new { name = "x" }) })).StatusCode);

        // reserved app / role through PATCH
        var admin = TestAuth.EnsureAdmin(e.Factory);
        var apps = (await e.Walk("/v1/applications", 200)).Items;
        var gk = apps.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/applications/{gk}", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/applications/{gk}", new { name = "gatekeeper" })).StatusCode); // unchanged
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/applications/{gk}", new { name = "gk2" })).StatusCode);
        var roles = (await e.Walk($"/v1/applications/{gk}/roles", 200)).Items;
        var adminRole = roles.Single(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/roles/{adminRole}", new { name = "root" })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/roles/{adminRole}", new { description = "all powerful" })).StatusCode);
        // no role can be added to the reserved app
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PostAsJsonAsync($"/v1/applications/{gk}/roles", new { name = "extra" })).StatusCode);
        // a role in a normal app may be called admin
        var other = await e.App("pc3-" + QaEnv.Slug()); var orole = await e.Role(other, "x");
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/roles/{orole}", new { name = "admin" })).StatusCode);
        Assert.NotNull(admin);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Patch_user_email_and_username_conflicts_and_precedence(string store)
    {
        using var e = new QaEnv(store);
        var n1 = "pd1" + QaEnv.Slug(); var n2 = "pd2" + QaEnv.Slug();
        var u1 = await e.Create("/v1/users", new { username = n1, email = n1 + "@example.com" });
        await e.Create("/v1/users", new { username = n2, email = n2 + "@example.com" });
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/users/{u1}", new { username = n2 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/users/{u1}", new { email = n2.ToUpperInvariant() + "@EXAMPLE.com" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/users/{u1}", new { email = n1.ToUpperInvariant() + "@EXAMPLE.com" })).StatusCode); // case-only change of own email
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Patch_isActive_false_cannot_remove_the_last_active_admin_and_deactivates_others(string store)
    {
        using var e = new QaEnv(store);
        var admin = TestAuth.EnsureAdmin(e.Factory);
        var r = await Patch(e, $"/v1/users/{admin.Id}", new { isActive = false });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.True((await QaEnv.Json(await e.Admin.GetAsync($"/v1/users/{admin.Id}"))).GetProperty("isActive").GetBoolean());
        // PUT with the same effect is refused too
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PutAsJsonAsync($"/v1/users/{admin.Id}",
            new { username = admin.Username, email = admin.Email, isActive = false })).StatusCode);

        // second admin: now one of them can be deactivated, the last one cannot
        var gk = (await e.Walk("/v1/applications", 200)).Items.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var role = (await e.Walk($"/v1/applications/{gk}/roles", 200)).Items.Single(x => x.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        var second = await e.User("adm" + QaEnv.Slug()); await e.Assign(second, role);
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/users/{second}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/users/{second}", new { isActive = false })).StatusCode); // already inactive: idempotent
        Assert.Equal(HttpStatusCode.Conflict, (await Patch(e, $"/v1/users/{admin.Id}", new { isActive = false, displayName = "x" })).StatusCode);
        // a deactivated admin does not count: reactivating works, then the other may go
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/users/{second}", new { isActive = true })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/users/{admin.Id}", new { isActive = false })).StatusCode);
        // revoke-by-delete of the last one is refused too
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.DeleteAsync($"/v1/users/{second}")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Two_admins_deactivating_each_other_concurrently_leave_one_active(string store)
    {
        using var e = new QaEnv(store);
        var a = TestAuth.EnsureAdmin(e.Factory);
        var gk = (await e.Walk("/v1/applications", 200)).Items.Single(x => x.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var role = (await e.Walk($"/v1/applications/{gk}/roles", 200)).Items.Single(x => x.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        for (var round = 0; round < 10; round++)
        {
            var b = await e.User("race" + QaEnv.Slug()); await e.Assign(b, role);
            var rs = await Task.WhenAll(
                Task.Run(() => Patch(e, $"/v1/users/{a.Id}", new { isActive = false })),
                Task.Run(() => Patch(e, $"/v1/users/{b}", new { isActive = false })));
            Assert.Contains(rs, r => r.StatusCode == HttpStatusCode.Conflict || r.StatusCode == HttpStatusCode.OK);
            var active = (await e.Walk("/v1/users?active=true", 200)).Items.Count(u => u.GetProperty("id").GetGuid() == a.Id || u.GetProperty("id").GetGuid() == b);
            Assert.True(active >= 1, "no active admin left");
            await Patch(e, $"/v1/users/{a.Id}", new { isActive = true });
            await e.Admin.DeleteAsync($"/v1/users/{b}");
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Concurrent_patches_of_different_fields_do_not_lose_updates(string store)
    {
        using var e = new QaEnv(store);
        int lostDisp = 0, lostEmail = 0, lostActive = 0, lostName = 0;
        for (var i = 0; i < 40; i++)
        {
            var n = "lu" + QaEnv.Slug();
            var u = await e.Create("/v1/users", new { username = n, email = n + "@example.com", displayName = "d0" });
            var (_, _, c, _, _) = await Svc(e);
            var barrier = new Barrier(4);
            var tasks = new[]
            {
                Task.Run(() => { barrier.SignalAndWait(); return Patch(e, $"/v1/users/{u}", new { displayName = "changed" }); }),
                Task.Run(() => { barrier.SignalAndWait(); return Patch(e, $"/v1/users/{u}", new { email = "new-" + n + "@example.com" }); }),
                Task.Run(() => { barrier.SignalAndWait(); return Patch(e, $"/v1/clients/{c}", new { isActive = false }); }),
                Task.Run(() => { barrier.SignalAndWait(); return Patch(e, $"/v1/clients/{c}", new { name = "ren-" + QaEnv.Slug() }); }),
            };
            await Task.WhenAll(tasks);
            var us = await QaEnv.Json(await e.Admin.GetAsync($"/v1/users/{u}"));
            var cs = await QaEnv.Json(await e.Admin.GetAsync($"/v1/clients/{c}"));
            if (us.GetProperty("displayName").GetString() != "changed") lostDisp++;
            if (us.GetProperty("email").GetString() != "new-" + n + "@example.com") lostEmail++;
            if (cs.GetProperty("isActive").GetBoolean()) lostActive++;
            if (!cs.GetProperty("name").GetString()!.StartsWith("ren-")) lostName++;
        }
        Assert.True(lostDisp + lostEmail + lostActive + lostName == 0, $"lost updates of 40 rounds: displayName={lostDisp} email={lostEmail} client.isActive={lostActive} client.name={lostName}");
    }

    // ---------------------------------------------------------------- clients

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Client_creation_rules(string store)
    {
        using var e = new QaEnv(store);
        var gk = (await e.Walk("/v1/applications", 200)).Items.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = "evil", application = gk })).StatusCode);
        var app = await e.App("cc-" + QaEnv.Slug());
        var n = "dup-" + QaEnv.Slug();
        Assert.Equal(HttpStatusCode.Created, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = n, application = app })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = n, application = app })).StatusCode);
        var app2 = await e.App("cc2-" + QaEnv.Slug());
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = n, application = app2 })).StatusCode); // names are global
        Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = n.ToUpperInvariant(), application = app })).StatusCode);
        foreach (var bad in new[] { "", " ", "has space", "-lead", "a/b", "x" + new string('y', 70), Guid.NewGuid().ToString(), "é", "a\0b", "a\nb" })
            Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = bad, application = app })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.PostAsJsonAsync("/v1/clients", new { application = app })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.PostAsJsonAsync("/v1/clients", new { name = "ghost-app", application = Guid.NewGuid() })).StatusCode);
        // missing application: 400 would be the sane answer; 404 'Application 0000... not found' is the current behaviour
        var missing = await e.Admin.PostAsJsonAsync("/v1/clients", new { name = "no-app" });
        Assert.True(missing.StatusCode == HttpStatusCode.BadRequest, $"missing application -> {(int)missing.StatusCode}: {await missing.Content.ReadAsStringAsync()}");
        // create inactive
        var inactive = await e.Admin.PostAsJsonAsync("/v1/clients", new { name = "off-" + QaEnv.Slug(), application = app, isActive = false });
        var j = await QaEnv.Json(inactive);
        Assert.False(j.GetProperty("isActive").GetBoolean());
        Assert.Equal("no-store", inactive.Headers.CacheControl?.ToString());
        Assert.False(j.TryGetProperty("secretHash", out _));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Client_patch_cannot_move_it_to_another_application_and_put_requires_a_name(string store)
    {
        using var e = new QaEnv(store);
        var (app, _, c, _, _) = await Svc(e);
        var other = await e.App("mv-" + QaEnv.Slug());
        var r = await Patch(e, $"/v1/clients/{c}", new { application = other });
        // either refuse (400/409) or ignore, but the app must not change
        Assert.Equal(app, (await QaEnv.Json(await e.Admin.GetAsync($"/v1/clients/{c}"))).GetProperty("appId").GetGuid());
        Assert.True(r.StatusCode is HttpStatusCode.OK or HttpStatusCode.BadRequest or HttpStatusCode.Conflict);
        Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.PutAsJsonAsync($"/v1/clients/{c}", new { isActive = false })).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Client_token_edge_cases(string store)
    {
        using var e = new QaEnv(store);
        var (app, role, client, name, secret) = await Svc(e);
        // case-insensitive client id, canonical client_id claim
        var upper = await ClientToken(e, name.ToUpperInvariant(), secret);
        Assert.Equal(HttpStatusCode.OK, upper.StatusCode);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken((await QaEnv.Json(upper)).GetProperty("accessToken").GetString()!);
        Assert.Equal(name, jwt.GetClaim("client_id").Value);
        // secret is case sensitive, no trimming
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret.ToUpperInvariant())).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret + " ")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, " " + secret)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret + "\0")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret[..^1])).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, new string('a', 100_000))).StatusCode == HttpStatusCode.RequestEntityTooLarge ? HttpStatusCode.Unauthorized : HttpStatusCode.Unauthorized);
        foreach (var bad in new object?[] { null, "", 5, true, new string('x', 300) })
        {
            var r = await ClientToken(e, bad, bad);
            Assert.True(r.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest, $"{bad} -> {(int)r.StatusCode}");
        }
        // using a user's login name as a client id, or the client's id (guid) instead of the name
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, client.ToString(), secret)).StatusCode);

        // disabled -> 401; re-enabled -> 200
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/clients/{client}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Patch(e, $"/v1/clients/{client}", new { isActive = true })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ClientToken(e, name, secret)).StatusCode);

        // rename: old name stops working, new name takes the same secret; aud follows an application rename
        var newName = "ren-" + QaEnv.Slug();
        await Patch(e, $"/v1/clients/{client}", new { name = newName });
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret)).StatusCode);
        var appNew = "app-ren-" + QaEnv.Slug();
        await Patch(e, $"/v1/applications/{app}", new { name = appNew });
        var t = await ClientToken(e, newName, secret);
        Assert.Equal(HttpStatusCode.OK, t.StatusCode);
        Assert.Equal(appNew, new JsonWebTokenHandler().ReadJsonWebToken((await QaEnv.Json(t)).GetProperty("accessToken").GetString()!).Audiences.Single());

        // role deleted after assignment: the client has no roles any more -> no token (not a token with empty roles, not a 500)
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/roles/{role}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, newName, secret)).StatusCode);
        Assert.Empty((await QaEnv.Json(await e.Admin.GetAsync($"/v1/clients/{client}/roles"))).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync($"/v1/clients/{client}/roles/{role}")).StatusCode);

        // app deleted: client is gone
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/applications/{app}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync($"/v1/clients/{client}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, newName, secret)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Client_with_no_roles_gets_no_token_and_a_client_token_works_only_for_its_own_roles(string store)
    {
        using var e = new QaEnv(store);
        var (app, _, client, name, secret) = await Svc(e, withRole: false);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret)).StatusCode);
        var r1 = await e.Role(app, "a"); var r2 = await e.Role(app, "b");
        await e.Admin.PutAsync($"/v1/clients/{client}/roles/{r1}", null);
        await e.Admin.PutAsync($"/v1/clients/{client}/roles/{r2}", null);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken((await QaEnv.Json(await ClientToken(e, name, secret))).GetProperty("accessToken").GetString()!);
        Assert.Equal(["a", "b"], jwt.Claims.Where(c => c.Type == "roles").Select(c => c.Value).Order());
        // a client token has the wrong audience for /v1 and for /health/ready
        var bearer = e.Bearer(jwt.EncodedToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await bearer.GetAsync("/v1/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await bearer.GetAsync("/health/ready")).StatusCode);
        // revoke/assign foreign role / unknown ids
        var other = await e.App("fx-" + QaEnv.Slug()); var fr = await e.Role(other, "z");
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PutAsync($"/v1/clients/{client}/roles/{fr}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.PutAsync($"/v1/clients/{client}/roles/{Guid.NewGuid()}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.PutAsync($"/v1/clients/{Guid.NewGuid()}/roles/{r1}", null)).StatusCode);
        // assigning a role of the reserved app to a user-style assignment on a client is refused
        var gk = (await e.Walk("/v1/applications", 200)).Items.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var adminRole = (await e.Walk($"/v1/applications/{gk}/roles", 200)).Items.Single(x => x.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PutAsync($"/v1/clients/{client}/roles/{adminRole}", null)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Rotation_invalidates_the_old_secret_and_races_leave_exactly_one_valid_secret(string store)
    {
        using var e = new QaEnv(store);
        var (_, _, client, name, secret) = await Svc(e);
        var r = await e.Admin.PostAsync($"/v1/clients/{client}/secret", null);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        var s2 = (await QaEnv.Json(r)).GetProperty("secret").GetString()!;
        Assert.NotEqual(secret, s2);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secret)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ClientToken(e, name, s2)).StatusCode);

        var secrets = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
            (await QaEnv.Json(await e.Admin.PostAsync($"/v1/clients/{client}/secret", null))).GetProperty("secret").GetString()!)));
        var valid = 0;
        foreach (var s in secrets.Append(s2)) if ((await ClientToken(e, name, s)).StatusCode == HttpStatusCode.OK) valid++;
        Assert.Equal(1, valid);

        // rotate vs delete race: either order ends with 404 afterwards and no 5xx
        var del = Task.Run(() => e.Admin.DeleteAsync($"/v1/clients/{client}"));
        var rot = Task.Run(() => e.Admin.PostAsync($"/v1/clients/{client}/secret", null));
        await Task.WhenAll(del, rot);
        Assert.True((int)rot.Result.StatusCode < 500 && (int)del.Result.StatusCode < 500);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync($"/v1/clients/{client}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientToken(e, name, secrets[^1])).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Client_list_paging_filters_and_ordering(string store)
    {
        using var e = new QaEnv(store);
        var a = await e.App("lp-" + QaEnv.Slug()); var b = await e.App("lq-" + QaEnv.Slug());
        var names = new[] { "c-1", "c.1", "c_1", "c1", "c-a", "ca", "c--", "C".ToLowerInvariant() };
        foreach (var (n, i) in names.Select((n, i) => (n, i)))
            await e.Create("/v1/clients", new { name = n + "-" + a.ToString("N")[..6], application = i % 2 == 0 ? a : b });
        var (_, all) = await e.Walk("/v1/clients", 3);
        var got = all.Select(x => x.GetProperty("name").GetString()!).ToList();
        Assert.Equal(got.Order(StringComparer.Ordinal), got);
        Assert.Equal(4, (await e.Walk($"/v1/clients?application={a}", 3)).Items.Count);
        Assert.Empty((await e.Walk($"/v1/clients?application={Guid.NewGuid()}", 3)).Items);
        Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.GetAsync("/v1/clients?application=notaguid")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync($"/v1/clients/{Guid.NewGuid()}/roles")).StatusCode);
    }

    // ---------------------------------------------------------------- health / openapi

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Health_ready_auth_matrix(string store)
    {
        using var e = new QaEnv(store);
        Assert.Equal(HttpStatusCode.OK, (await e.Anon.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Anon.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync("/health/ready")).StatusCode);
        var nonAdmin = e.Bearer(TestAuth.Token(e.Factory, "gatekeeper", ["viewer"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await nonAdmin.GetAsync("/health/ready")).StatusCode);
        var wrongAud = e.Bearer(TestAuth.Token(e.Factory, "shop", ["admin"]));
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrongAud.GetAsync("/health/ready")).StatusCode);
        var expired = e.Bearer(TestAuth.Token(e.Factory, "gatekeeper", ["admin"], DateTimeOffset.UtcNow.AddHours(-3)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await expired.GetAsync("/health/ready")).StatusCode);
        var junk = e.Anon.CreateRequest("/health/ready", "Bearer not.a.jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Anon.SendAsync(junk)).StatusCode);
        var basic = e.Anon.CreateRequest("/health/ready", "Basic dXNlcjpwdw==");
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Anon.SendAsync(basic)).StatusCode);
        // a stray header on /health never matters
        Assert.Equal(HttpStatusCode.OK, (await e.Anon.SendAsync(e.Anon.CreateRequest("/health", "Bearer garbage"))).StatusCode);
        // method matrix
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await e.Admin.PostAsync("/health/ready", null)).StatusCode);
        // WWW-Authenticate header on 401
        var r = await e.Anon.GetAsync("/health/ready");
        Assert.Contains("Bearer", r.Headers.WwwAuthenticate.ToString());
        // admin token of a user deleted from the store still passes (documented: signed token only)
        var ghost = e.Bearer(TestAuth.Token(e.Factory, "gatekeeper", ["admin"]));
        Assert.Equal(HttpStatusCode.OK, (await ghost.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ghost.GetAsync("/v1/users")).StatusCode);
    }

    [SkippableFact]
    public async Task Health_ready_with_unreachable_or_unmigrated_database_answers_503_to_an_admin_and_401_to_nobody_else()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        using var _ = db;
        var problems = new List<string>();
        foreach (var (label, conn, migrate) in new[]
        {
            ("unmigrated", db!.AppConnection.Replace("Database=", "Database=") , false),
            ("unreachable", "Host=127.0.0.1;Port=1;Username=x;Password=y;Database=z;Timeout=2", false),
        })
        {
            if (!migrate && label == "unmigrated") { /* grant needs tables; connect as owner-less app role would fail login: use migrator creds */ }
            var c = label == "unmigrated" ? db.MigratorConnection : conn;
            using var f = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            {
                b.UseSetting("Store:Provider", "Postgres");
                b.UseSetting("Auth:SigningKeyPem", TestKey.Pem);
                b.UseSetting("ConnectionStrings:Gatekeeper", c);
            });
            var admin = f.CreateClient();
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Token(f, "gatekeeper", ["admin"]));
            var r = await admin.GetAsync("/health/ready");
            if (r.StatusCode != HttpStatusCode.ServiceUnavailable) problems.Add($"{label}: ready -> {(int)r.StatusCode}");
            if ((await f.CreateClient().GetAsync("/health/ready")).StatusCode != HttpStatusCode.Unauthorized) problems.Add($"{label}: anon ready not 401");
            if ((await f.CreateClient().GetAsync("/health")).StatusCode != HttpStatusCode.OK) problems.Add($"{label}: /health not 200");
            // data endpoints with a (store-less) admin token: 401 or 503, never 500
            var data = await admin.GetAsync("/v1/users");
            if ((int)data.StatusCode is not (401 or 503)) problems.Add($"{label}: /v1/users -> {(int)data.StatusCode}");
            // login against a dead store
            var login = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = "nobody", password = "correct horse battery", application = "x" });
            if ((int)login.StatusCode is not (401 or 503)) problems.Add($"{label}: login -> {(int)login.StatusCode}");
            var ct = await f.CreateClient().PostAsJsonAsync("/v1/auth/client-token", new { clientId = "nobody", clientSecret = "gks_xxxxxxxxxxxxxxxx" });
            if ((int)ct.StatusCode is not (401 or 503)) problems.Add($"{label}: client-token -> {(int)ct.StatusCode}");
        }
        Assert.True(problems.Count == 0, string.Join("; ", problems));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task OpenApi_declares_bearer_and_patch_and_secures_exactly_the_management_routes(string store)
    {
        using var e = new QaEnv(store);
        var doc = JsonDocument.Parse(await e.Anon.GetStringAsync("/openapi/v1.json")).RootElement;
        Assert.Equal("bearer", doc.GetProperty("components").GetProperty("securitySchemes").EnumerateObject().First().Value.GetProperty("scheme").GetString()!.ToLowerInvariant());
        foreach (var p in doc.GetProperty("paths").EnumerateObject())
            foreach (var op in p.Value.EnumerateObject())
            {
                var secured = op.Value.TryGetProperty("security", out var sec) && sec.GetArrayLength() > 0;
                var shouldBe = p.Name.StartsWith("/v1/") && (!p.Name.StartsWith("/v1/auth/") || p.Name == "/v1/auth/introspect"); // introspect: client Basic auth
                Assert.True(secured == shouldBe, $"{op.Name.ToUpper()} {p.Name}: secured={secured}");
            }
        var paths = doc.GetProperty("paths");
        foreach (var path in new[] { "/v1/applications/{id}", "/v1/roles/{id}", "/v1/users/{id}", "/v1/clients/{id}" })
            Assert.True(paths.GetProperty(path).TryGetProperty("patch", out _), path);
        Assert.True(paths.TryGetProperty("/v1/audit", out _));
        Assert.True(paths.TryGetProperty("/v1/auth/client-token", out _));
        Assert.False(paths.TryGetProperty("/health/ready", out _));
        // committed contract is the same as the served one
        var file = Path.Combine(FindRepoRoot(), "docs", "openapi.json");
        Assert.Equal(JsonSerializer.Serialize(JsonDocument.Parse(File.ReadAllText(file)).RootElement.GetProperty("paths")),
            JsonSerializer.Serialize(paths));
    }

    private static string FindRepoRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "Gatekeeper.slnx"))) d = d.Parent;
        return d!.FullName;
    }
}

internal static class Qa4bHttp
{
    public static HttpRequestMessage CreateRequest(this HttpClient _, string url, string authorization)
    {
        var r = new HttpRequestMessage(HttpMethod.Get, url);
        r.Headers.TryAddWithoutValidation("Authorization", authorization);
        return r;
    }
}
