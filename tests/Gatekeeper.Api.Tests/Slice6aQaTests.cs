using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA for slice 6a. Every test runs on a fresh in-memory store and, when GATEKEEPER_TEST_PG is set, on Postgres.</summary>
public class Slice6aQaTests
{
    private const string Password = "correct horse battery";

    public static IEnumerable<object[]> Stores() => [["memory"], ["postgres"]];

    private sealed class Env : IDisposable
    {
        public WebApplicationFactory<Program> F = null!;
        public HttpClient Admin = null!;
        public PgTestDatabase? Db;

        public static Env Create(string store)
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
            return e;
        }

        public void Dispose() { F.Dispose(); Db?.Dispose(); }

        public async Task<JsonElement> Post(string url, object body)
        {
            var r = await Admin.PostAsJsonAsync(url, body);
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }

        public async Task<(string Name, Guid Id)> App(params string[] roles)
        {
            var name = "app-" + Guid.NewGuid().ToString("N")[..10];
            var id = (await Post("/v1/applications", new { name })).GetProperty("id").GetGuid();
            foreach (var r in roles) await Post($"/v1/applications/{id}/roles", new { name = r });
            return (name, id);
        }

        public async Task<Guid> Role(Guid appId, string name) =>
            (await Admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{appId}/roles?limit=200")).GetProperty("items").EnumerateArray()
                .Single(r => r.GetProperty("name").GetString() == name).GetProperty("id").GetGuid();

        public async Task<(string Name, Guid Id)> User(DateTimeOffset? testExpiry = null)
        {
            var name = "u-" + Guid.NewGuid().ToString("N")[..10];
            object body = testExpiry is { } e
                ? new { username = name, email = $"{name}@example.com", kind = "test", expiresAt = e }
                : new { username = name, email = $"{name}@example.com" };
            var id = (await Post("/v1/users", body)).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            return (name, id);
        }

        public async Task Grant(Guid user, Guid role) =>
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsync($"/v1/users/{user}/roles/{role}", null)).StatusCode);

        public async Task<JsonElement> Login(string user, string app, string? password = null)
        {
            var r = await F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = password ?? (user == TestAuth.AdminName ? TestAuth.AdminPassword : Password), application = app, refresh = true });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }

        public Task<HttpResponseMessage> Refresh(JsonElement login) =>
            F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = login.GetProperty("refreshToken").GetString() });

        public async Task<JsonElement> Sessions(Guid user) =>
            (await Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{user}/sessions?limit=200")).GetProperty("items");

        public async Task<(string Id, string Secret)> Verifier(Guid appId)
        {
            var v = await Post("/v1/clients", new { name = "ver-" + Guid.NewGuid().ToString("N")[..10], application = appId });
            return (v.GetProperty("name").GetString()!, v.GetProperty("secret").GetString()!);
        }

        public async Task<bool> Active((string Id, string Secret) v, string token)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token }) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{v.Id}:{v.Secret}")));
            var r = await F.CreateClient().SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean();
        }

        public async Task<string> LatestAudit(string needle)
        {
            var s = await Admin.GetStringAsync("/v1/audit?limit=200");
            return s.Contains(needle) ? needle : "";
        }

        public async Task<(Guid Id, string Name)> SecondAdmin()
        {
            var gk = Domain.Reserved.AdminApp;
            var apps = (await Admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray()
                .Single(a => a.GetProperty("name").GetString() == gk).GetProperty("id").GetGuid();
            var role = await Role(apps, Domain.Reserved.AdminRole);
            var u = await User();
            await Grant(u.Id, role);
            return (u.Id, u.Name);
        }

        public async Task<Guid> AdminRoleId()
        {
            var apps = (await Admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray()
                .Single(a => a.GetProperty("name").GetString() == Domain.Reserved.AdminApp).GetProperty("id").GetGuid();
            return await Role(apps, Domain.Reserved.AdminRole);
        }
    }

    private static DateTimeOffset Sec(JsonElement session) => session.GetProperty("expiresAt").GetDateTimeOffset();

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Last_admin_409_via_put_and_patch_leaves_sessions_and_audit_clean(string store)
    {
        using var e = Env.Create(store);
        var me = TestAuth.EnsureAdmin(e.F);
        var l1 = await e.Login(TestAuth.AdminName, "gatekeeper");
        await e.Login(TestAuth.AdminName, "gatekeeper");
        var cur = await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{me.Id}");

        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PatchAsJsonAsync($"/v1/users/{me.Id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.PutAsJsonAsync($"/v1/users/{me.Id}",
            new { username = TestAuth.AdminName, email = cur.GetProperty("email").GetString(), isActive = false })).StatusCode);
        // demotion to a service/test kind is also refused and must not cap or revoke
        Assert.Equal(HttpStatusCode.Conflict, (await e.Admin.DeleteAsync($"/v1/users/{me.Id}/roles/{await e.AdminRoleId()}")).StatusCode);

        Assert.Equal(2, (await e.Sessions(me.Id)).GetArrayLength());
        Assert.Equal(HttpStatusCode.OK, (await e.Refresh(l1)).StatusCode);
        Assert.DoesNotContain("sessionsRevoked", await e.Admin.GetStringAsync("/v1/audit?limit=200"));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Last_admin_converted_to_test_with_expiry_is_refused_and_does_not_cap(string store)
    {
        using var e = Env.Create(store);
        var me = TestAuth.EnsureAdmin(e.F);
        await e.Login(TestAuth.AdminName, "gatekeeper");
        var before = Sec((await e.Sessions(me.Id))[0]);
        var r = await e.Admin.PatchAsJsonAsync($"/v1/users/{me.Id}", new { kind = "test", expiresAt = DateTimeOffset.UtcNow.AddMinutes(5) });
        Assert.True(r.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.BadRequest, r.StatusCode.ToString());
        Assert.Equal(before, Sec((await e.Sessions(me.Id))[0]));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Deactivating_a_non_last_admin_revokes_their_admin_sessions(string store)
    {
        using var e = Env.Create(store);
        var second = await e.SecondAdmin();
        var login = await e.Login(second.Name, "gatekeeper");
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{second.Id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Refresh(login)).StatusCode);
        Assert.Equal(0, (await e.Sessions(second.Id)).GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Access_token_with_sid_stays_inactive_after_reactivation_and_introspection_matches(string store)
    {
        using var e = Env.Create(store);
        var app = await e.App("member");
        var role = await e.Role(app.Id, "member");
        var u = await e.User();
        await e.Grant(u.Id, role);
        var v = await e.Verifier(app.Id);
        var login = await e.Login(u.Name, app.Name);
        var access = login.GetProperty("accessToken").GetString()!;
        Assert.True(await e.Active(v, access));

        await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false });
        Assert.False(await e.Active(v, access));
        await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = true });
        Assert.False(await e.Active(v, access)); // session is gone for good
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Refresh(login)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Last_role_per_application_edge_cases(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("r1", "r2");
        var b = await e.App("r1"); // same role name in another app
        var r1 = await e.Role(a.Id, "r1"); var r2 = await e.Role(a.Id, "r2"); var rb = await e.Role(b.Id, "r1");
        var u = await e.User(); var w = await e.User();
        await e.Grant(u.Id, r1); await e.Grant(u.Id, r2); await e.Grant(u.Id, rb); await e.Grant(w.Id, r1);
        var la = await e.Login(u.Name, a.Name); var lb = await e.Login(u.Name, b.Name); var lw = await e.Login(w.Name, a.Name);

        await e.Admin.DeleteAsync($"/v1/users/{u.Id}/roles/{r1}");
        Assert.Equal(2, (await e.Sessions(u.Id)).GetArrayLength());           // r2 still held in a
        Assert.Equal(HttpStatusCode.OK, (await e.Refresh(la)).StatusCode);
        await e.Admin.DeleteAsync($"/v1/users/{u.Id}/roles/{r2}");
        Assert.Equal(1, (await e.Sessions(u.Id)).GetArrayLength());           // a's session gone, b's stays
        Assert.Equal(HttpStatusCode.OK, (await e.Refresh(lb)).StatusCode);
        Assert.Equal(1, (await e.Sessions(w.Id)).GetArrayLength());
        Assert.Equal(HttpStatusCode.OK, (await e.Refresh(lw)).StatusCode);
        // deleting from a user that has no such assignment: 404, nothing revoked
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync($"/v1/users/{w.Id}/roles/{rb}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync($"/v1/users/{Guid.NewGuid()}/roles/{rb}")).StatusCode);
        Assert.Equal(1, (await e.Sessions(w.Id)).GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Role_removal_on_an_already_inactive_user_is_harmless(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("r1");
        var r1 = await e.Role(a.Id, "r1");
        var u = await e.User();
        await e.Grant(u.Id, r1);
        await e.Login(u.Name, a.Name);
        await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false });
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/users/{u.Id}/roles/{r1}")).StatusCode);
        Assert.Equal(0, (await e.Sessions(u.Id)).GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Removing_the_admin_role_from_a_non_last_admin_ends_their_admin_sessions_but_not_others(string store)
    {
        using var e = Env.Create(store);
        var second = await e.SecondAdmin();
        var other = await e.App("m");
        await e.Grant(second.Id, await e.Role(other.Id, "m"));
        var admin = await e.Login(second.Name, "gatekeeper");
        var elsewhere = await e.Login(second.Name, other.Name);
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync($"/v1/users/{second.Id}/roles/{await e.AdminRoleId()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.Refresh(admin)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Refresh(elsewhere)).StatusCode);
        Assert.Equal(1, (await e.Sessions(second.Id)).GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Expiry_cap_matrix(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("m");
        var role = await e.Role(a.Id, "m");
        var far = DateTimeOffset.UtcNow.AddDays(30);
        var t = await e.User(far);
        var bystander = await e.User(far);
        await e.Grant(t.Id, role); await e.Grant(bystander.Id, role);
        await e.Login(t.Name, a.Name); await e.Login(bystander.Name, a.Name);
        var original = Sec((await e.Sessions(t.Id))[0]);
        Assert.True(original <= far.AddSeconds(1));

        // same expiry again: no cap, no note
        await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { displayName = "x" });
        Assert.Equal(original, Sec((await e.Sessions(t.Id))[0]));

        // earlier
        var soon = DateTimeOffset.UtcNow.AddDays(1);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { expiresAt = soon })).StatusCode);
        Assert.Equal(soon, Sec((await e.Sessions(t.Id))[0]), TimeSpan.FromSeconds(1));
        Assert.Equal(original, Sec((await e.Sessions(bystander.Id))[0]));   // other user untouched

        // later: no lengthening
        await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { expiresAt = DateTimeOffset.UtcNow.AddDays(60) });
        Assert.Equal(soon, Sec((await e.Sessions(t.Id))[0]), TimeSpan.FromSeconds(1));

        // test -> person: no cap, no lengthening
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { kind = "person" })).StatusCode);
        Assert.Equal(soon, Sec((await e.Sessions(t.Id))[0]), TimeSpan.FromSeconds(1));

        // person -> test with an expiry in the past: must not leave a usable session behind
        var r = await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { kind = "test", expiresAt = DateTimeOffset.UtcNow.AddHours(-1) });
        if (r.IsSuccessStatusCode) Assert.Equal(0, (await e.Sessions(t.Id)).GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Put_that_sets_a_null_expiry_on_a_test_user_does_not_break_sessions(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("m");
        var t = await e.User(DateTimeOffset.UtcNow.AddDays(5));
        await e.Grant(t.Id, await e.Role(a.Id, "m"));
        var login = await e.Login(t.Name, a.Name);
        var cur = await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{t.Id}");
        var r = await e.Admin.PutAsJsonAsync($"/v1/users/{t.Id}", new { username = t.Name, email = cur.GetProperty("email").GetString(), kind = "test", expiresAt = (DateTimeOffset?)null });
        Assert.True(r.StatusCode is HttpStatusCode.OK, await r.Content.ReadAsStringAsync()); // null keeps the expiry
        Assert.Equal(HttpStatusCode.OK, (await e.Refresh(login)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Expired_test_user_sessions_are_not_counted_or_touched(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("m");
        var t = await e.User(DateTimeOffset.UtcNow.AddDays(2));
        await e.Grant(t.Id, await e.Role(a.Id, "m"));
        await e.Login(t.Name, a.Name);
        // Deactivate with one active session: counted exactly once and audited.
        await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { isActive = false });
        Assert.Contains("sessionsRevoked=1", await e.Admin.GetStringAsync("/v1/audit?limit=200"));
        // Deactivating again (already inactive) revokes nothing and notes nothing new.
        var before = (await e.Admin.GetStringAsync("/v1/audit?limit=200")).Split("sessionsRevoked=1").Length;
        await e.Admin.PatchAsJsonAsync($"/v1/users/{t.Id}", new { isActive = false });
        Assert.Equal(before, (await e.Admin.GetStringAsync("/v1/audit?limit=200")).Split("sessionsRevoked=1").Length);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Concurrent_deactivation_and_updates_do_not_leave_live_sessions(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("m");
        var role = await e.Role(a.Id, "m");
        var u = await e.User(DateTimeOffset.UtcNow.AddDays(10));
        await e.Grant(u.Id, role);
        for (var i = 0; i < 5; i++) await e.Login(u.Name, a.Name);

        var tasks = new List<Task<HttpResponseMessage>>();
        for (var i = 0; i < 6; i++)
        {
            tasks.Add(e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false }));
            tasks.Add(e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { expiresAt = DateTimeOffset.UtcNow.AddDays(1 + i) }));
            tasks.Add(e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { displayName = "n" + i }));
        }
        var rs = await Task.WhenAll(tasks);
        Assert.All(rs, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Equal(0, (await e.Sessions(u.Id)).GetArrayLength());
        var user = await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}");
        Assert.False(user.GetProperty("isActive").GetBoolean());
        var audit = await e.Admin.GetStringAsync("/v1/audit?limit=200");
        // total revoked across audit rows must equal the 5 created sessions (no double counting) and none are capped-and-revoked twice
        Assert.Equal(1, audit.Split("sessionsRevoked=5").Length - 1);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Concurrent_last_admin_deactivation_race_leaves_one_admin_active(string store)
    {
        using var e = Env.Create(store);
        var me = TestAuth.EnsureAdmin(e.F);
        var second = await e.SecondAdmin();
        await e.Login(TestAuth.AdminName, "gatekeeper"); await e.Login(second.Name, "gatekeeper");
        var rs = await Task.WhenAll(
            e.Admin.PatchAsJsonAsync($"/v1/users/{me.Id}", new { isActive = false }),
            e.Admin.PatchAsJsonAsync($"/v1/users/{second.Id}", new { isActive = false }));
        Assert.Single(rs, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(rs, r => r.StatusCode == HttpStatusCode.Conflict);
        var live = (await e.Sessions(me.Id)).GetArrayLength() + (await e.Sessions(second.Id)).GetArrayLength();
        Assert.Equal(1, live);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Deactivation_note_has_revoked_count_only_when_nonzero_and_capped_count_independently(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("m");
        var u = await e.User(DateTimeOffset.UtcNow.AddDays(9));
        await e.Grant(u.Id, await e.Role(a.Id, "m"));
        await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false }); // no sessions
        Assert.DoesNotContain("sessionsRevoked", await e.Admin.GetStringAsync("/v1/audit?limit=200"));
        await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = true });
        await e.Login(u.Name, a.Name); await e.Login(u.Name, a.Name);
        // deactivate and shorten in one request: only revocation is meaningful, but the note must not claim capped sessions that were revoked
        await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false, expiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        var audit = await e.Admin.GetStringAsync("/v1/audit?limit=200");
        Assert.Contains("sessionsRevoked=2", audit);
        Assert.DoesNotContain("sessionsCapped=2", audit);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Failed_validation_changes_nothing(string store)
    {
        using var e = Env.Create(store);
        var a = await e.App("m");
        var u = await e.User();
        await e.Grant(u.Id, await e.Role(a.Id, "m"));
        await e.Login(u.Name, a.Name);
        Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false, email = "not-an-email" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.PatchAsJsonAsync($"/v1/users/{Guid.NewGuid()}", new { isActive = false })).StatusCode);
        Assert.Equal(1, (await e.Sessions(u.Id)).GetArrayLength());
    }
}
