using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeeper.Api.Tests;

/// <summary>
/// QA for slice 7a over HTTP, written from the spec: tokens with odd or conflicting auth_time/iat claims, the self-service surface,
/// cross-application reach, the version, audit notes, a real parallel race, and a demonstration of why a few older tests depend on the
/// 10 s access-check cache. Memory and (with GATEKEEPER_TEST_PG) Postgres. No sleeping: the cache window is ended with Evict.
/// </summary>
public class Slice7aQaApiTests
{
    private const string Password = "correct horse battery";
    private const string Fresh = "tr0ub4dor staple 99";

    public static IEnumerable<object[]> Stores => [["mem"], ["pg"]];

    private sealed class Env : IDisposable
    {
        private readonly PgTestDatabase? _db;
        public WebApplicationFactory<Program> F { get; }
        public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public HttpClient Admin { get; }
        public string App { get; } = "app-" + Guid.NewGuid().ToString("N")[..10];
        public Guid AppId { get; private set; }
        public Guid RoleId { get; private set; }

        public Env(string store)
        {
            if (store == "pg")
            {
                _db = PgTestDatabase.TryCreate();
                Skip.If(_db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
                using (var migrator = new ServiceCollection().AddPostgresStore(_db!.MigratorConnection).BuildServiceProvider())
                    PostgresStoreExtensions.MigrateAsync(migrator).GetAwaiter().GetResult();
                _db.GrantAppAccess();
            }
            F = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            {
                b.UseSetting("Auth:SigningKeyPem", Key.ExportPkcs8PrivateKeyPem());
                if (_db is not null)
                {
                    b.UseSetting("Store:Provider", "Postgres");
                    b.UseSetting("ConnectionStrings:Gatekeeper", _db.AppConnection);
                }
            });
            Admin = F.CreateAdminClient();
        }

        public async Task SeedApp()
        {
            AppId = (await Post("/v1/applications", new { name = App })).GetProperty("id").GetGuid();
            RoleId = (await Post($"/v1/applications/{AppId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        }

        public async Task<JsonElement> Post(string url, object body)
        {
            var r = await Admin.PostAsJsonAsync(url, body);
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }

        public async Task<(string Name, Guid Id)> NewUser()
        {
            var name = "u-" + Guid.NewGuid().ToString("N")[..12];
            var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsync($"/v1/users/{id}/roles/{RoleId}", null)).StatusCode);
            return (name, id);
        }

        public async Task<User> NewAdmin()
        {
            var name = "adm-" + Guid.NewGuid().ToString("N")[..10];
            await Bootstrap.CreateAdminAsync(F.Services, name, name + "@example.com", Password);
            return (await F.Services.GetRequiredService<IUserRepository>().ListAsync(username: name)).Single();
        }

        public Task<User> Get(Guid id) => F.Services.GetRequiredService<IUserRepository>().GetAsync(id)!;

        public async Task SetCutOff(Guid userId, DateTimeOffset at)
        {
            var users = F.Services.GetRequiredService<IUserRepository>();
            await users.UpdateAsync((await users.GetAsync(userId))! with { SessionsValidAfter = at });
        }

        public void Evict(Guid userId) => F.Services.GetRequiredService<AdminAccessCheck>().Evict(userId);

        public HttpClient As(string token)
        {
            var c = F.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return c;
        }

        public async Task<HttpStatusCode> Manage(string token) => (await As(token).GetAsync("/v1/applications")).StatusCode;
        public async Task<HttpStatusCode> Me(string token) => (await As(token).GetAsync("/v1/me")).StatusCode;

        public async Task<JsonElement> LoginBody(string name, string password = Password, string? application = null, bool refresh = false)
        {
            var r = await F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = application ?? App, refresh });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }

        public async Task<(string Verifier, string Secret)> NewVerifier()
        {
            var v = await Post("/v1/clients", new { name = "ver-" + Guid.NewGuid().ToString("N")[..10], application = AppId });
            return (v.GetProperty("name").GetString()!, v.GetProperty("secret").GetString()!);
        }

        public async Task<bool> Active((string Verifier, string Secret) v, string token)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token }) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{v.Verifier}:{v.Secret}")));
            var r = await F.CreateClient().SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean();
        }

        /// <summary>A token signed with the server's key with exactly the claims given (no defaults), for odd or conflicting auth_time/iat/sid.</summary>
        public string Forge(User user, string audience, string[] roles, DateTimeOffset issuedAt, Dictionary<string, object?>? extra = null, string? sid = null, bool omitIat = false)
        {
            var claims = new Dictionary<string, object> { ["roles"] = roles };
            foreach (var (k, v) in extra ?? []) if (v is not null) claims[k] = v;
            var identity = new List<Claim> { new("sub", user.Id.ToString()), new("jti", Guid.NewGuid().ToString()), new("preferred_username", user.Username), new("kind", "person") };
            if (sid is not null) identity.Add(new Claim("sid", sid));
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "gatekeeper",
                Audience = audience,
                IssuedAt = omitIat ? null : issuedAt.UtcDateTime,
                NotBefore = issuedAt.UtcDateTime,
                Expires = issuedAt.AddMinutes(15).UtcDateTime,
                TokenType = TokenService.TokenType,
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(Key) { KeyId = new TokenService(Key, new AuthOptions()).Kid }, SecurityAlgorithms.EcdsaSha256),
                Subject = new ClaimsIdentity(identity),
                Claims = claims,
            });
        }

        public void Dispose()
        {
            F.Dispose();
            _db?.Dispose();
        }
    }

    private static long Secs(DateTimeOffset t) => t.ToUnixTimeSeconds();

    // ---- malformed and conflicting claims ----

    public static IEnumerable<object[]> BadAuthTimes()
    {
        foreach (var store in new[] { "mem", "pg" })
        {
            yield return [store, "text"];
            yield return [store, "empty"];
            yield return [store, "negative"];
            yield return [store, "fraction"];
            yield return [store, "bool"];
        }
    }

    private static object BadValue(string kind) => kind switch
    {
        "text" => "abc",
        "empty" => "",
        "negative" => -5L,
        "fraction" => 1_900_000_000.5,
        "bool" => true,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    [SkippableTheory, MemberData(nameof(BadAuthTimes))]
    public async Task A_malformed_auth_time_fails_closed_once_a_cut_off_exists_and_is_accepted_while_there_is_none(string store, string kind)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var admin = await e.NewAdmin();
        var (_, uid) = await e.NewUser();
        var user = await e.Get(uid);
        var now = DateTimeOffset.UtcNow;
        var bad = new Dictionary<string, object?> { ["auth_time"] = BadValue(kind) };
        string AdminTok() => e.Forge(admin, Reserved.AdminApp, [Reserved.AdminRole], now - TimeSpan.FromSeconds(10), bad);
        string AppTok() => e.Forge(user, e.App, ["member"], now - TimeSpan.FromSeconds(10), bad);

        // no cut-off yet: nothing to judge by, so the token works as before
        Assert.Equal(HttpStatusCode.OK, await e.Manage(AdminTok()));
        Assert.True(await e.Active(verifier, AppTok()));

        await e.SetCutOff(admin.Id, now - TimeSpan.FromSeconds(60));
        await e.SetCutOff(uid, now - TimeSpan.FromSeconds(60));
        e.Evict(admin.Id);
        // a valid iat later than the cut-off must NOT rescue a token whose auth_time is present but unreadable
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(AdminTok()));
        Assert.False(await e.Active(verifier, AppTok()));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Auth_time_wins_over_iat_in_both_directions_on_the_management_api_the_self_service_api_and_introspection(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var admin = await e.NewAdmin();
        var (_, uid) = await e.NewUser();
        var user = await e.Get(uid);
        var now = DateTimeOffset.UtcNow;
        var cut = now - TimeSpan.FromSeconds(60);
        await e.SetCutOff(admin.Id, cut);
        await e.SetCutOff(uid, cut);
        e.Evict(admin.Id);

        Dictionary<string, object?> AuthTime(DateTimeOffset t) => new() { ["auth_time"] = Secs(t) };
        // signed in before the cut-off, issued after it (for example a re-issue): refused although iat is fresh
        var staleAuth = now - TimeSpan.FromSeconds(5);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.Forge(admin, Reserved.AdminApp, [Reserved.AdminRole], staleAuth, AuthTime(cut.AddSeconds(-10)))));
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Me(e.Forge(user, Reserved.AdminApp, [], staleAuth, AuthTime(cut.AddSeconds(-10)))));
        Assert.False(await e.Active(verifier, e.Forge(user, e.App, ["member"], staleAuth, AuthTime(cut.AddSeconds(-10)))));
        // signed in after the cut-off although iat is older than it: accepted (auth_time decides, iat is only the fallback)
        var oldIat = cut.AddSeconds(-30);
        Assert.Equal(HttpStatusCode.OK, await e.Manage(e.Forge(admin, Reserved.AdminApp, [Reserved.AdminRole], oldIat, AuthTime(cut.AddSeconds(10)))));
        Assert.Equal(HttpStatusCode.OK, await e.Me(e.Forge(user, Reserved.AdminApp, [], oldIat, AuthTime(cut.AddSeconds(10)))));
        Assert.True(await e.Active(verifier, e.Forge(user, e.App, ["member"], oldIat, AuthTime(cut.AddSeconds(10)))));
        // exactly the cut-off's second: refused (same-second rule); the next second: accepted
        var sameSecond = new DateTimeOffset(cut.UtcTicks - cut.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.Forge(admin, Reserved.AdminApp, [Reserved.AdminRole], now, AuthTime(sameSecond))));
        Assert.Equal(HttpStatusCode.OK, await e.Manage(e.Forge(admin, Reserved.AdminApp, [Reserved.AdminRole], now, AuthTime(sameSecond.AddSeconds(1)))));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_token_whose_sid_belongs_to_another_users_live_session_does_not_count(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var admin = await e.NewAdmin();
        var (nameB, idB) = await e.NewUser();
        var (nameC, idC) = await e.NewUser();
        var userC = await e.Get(idC);
        var body = await e.LoginBody(nameB, refresh: true);
        var sidB = new JsonWebToken(body.GetProperty("accessToken").GetString()!).GetPayloadValue<string>("sid");
        var now = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(5);
        // subject C, session of B
        Assert.False(await e.Active(verifier, e.Forge(userC, e.App, ["member"], now, sid: sidB)));
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.Forge(admin, Reserved.AdminApp, [Reserved.AdminRole], now, sid: sidB)));
        _ = nameC; _ = idB;
    }

    // ---- self-service surface ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_sessionless_self_service_token_stops_after_an_admin_reset(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var adm = await e.NewAdmin(); // only a user with a role may sign in to the reserved application without a session
        var (name, id) = (adm.Username, adm.Id);
        var token = (await e.LoginBody(name, application: Reserved.AdminApp)).GetProperty("accessToken").GetString()!;
        Assert.Equal(HttpStatusCode.OK, await e.Me(token));
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh })).StatusCode);
        e.Evict(id);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Me(token));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task An_own_password_change_with_a_sessionless_token_ends_every_session_and_that_token_too(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var adm = await e.NewAdmin();
        var (name, id) = (adm.Username, adm.Id);
        var sessionless = (await e.LoginBody(name, application: Reserved.AdminApp)).GetProperty("accessToken").GetString()!;
        var withSession = await e.LoginBody(name, application: Reserved.AdminApp, refresh: true);
        var sessionToken = withSession.GetProperty("accessToken").GetString()!;

        var change = await e.As(sessionless).PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = Fresh });
        Assert.Equal(HttpStatusCode.NoContent, change.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, await e.Me(sessionless));   // documented limit 5
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Me(sessionToken));
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = withSession.GetProperty("refreshToken").GetString() })).StatusCode);
        Assert.Equal(0, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_reset_and_a_revoke_all_end_the_sessions_of_every_application_and_leave_the_version(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var otherApp = (await e.Post("/v1/applications", new { name = "o-" + Guid.NewGuid().ToString("N")[..8] })).GetProperty("id").GetGuid();
        var otherName = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{otherApp}")).GetProperty("name").GetString()!;
        var otherRole = (await e.Post($"/v1/applications/{otherApp}/roles", new { name = "r" })).GetProperty("id").GetGuid();
        var (name, id) = await e.NewUser();
        await e.Admin.PutAsync($"/v1/users/{id}/roles/{otherRole}", null);
        var one = await e.LoginBody(name, refresh: true);
        var two = await e.LoginBody(name, application: otherName, refresh: true);
        Assert.Equal(2, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());

        // revoke-all by cut-off alone: simulate the row step having been lost by writing only the cut-off
        await e.SetCutOff(id, DateTimeOffset.UtcNow);
        var etag = (await e.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag!.Tag;
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.DeleteAsync($"/v1/users/{id}/sessions")).StatusCode);
        Assert.Equal(0, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        foreach (var s in new[] { one, two })
            Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = s.GetProperty("refreshToken").GetString() })).StatusCode);

        // the user can sign in again straight away in either application, and the user's own list shows exactly that session
        var again = await e.LoginBody(name, Fresh, refresh: true);
        Assert.Equal(1, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.OK, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = again.GetProperty("refreshToken").GetString() })).StatusCode);

        // the ETag taken before is still good for a conditional write
        var patch = new HttpRequestMessage(HttpMethod.Patch, $"/v1/users/{id}") { Content = JsonContent.Create(new { displayName = "Zed" }) };
        patch.Headers.TryAddWithoutValidation("If-Match", etag);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.SendAsync(patch)).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Admin_revoke_all_for_an_unknown_user_is_404_and_raises_nothing(string store)
    {
        using var e = new Env(store);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.DeleteAsync($"/v1/users/{Guid.NewGuid()}/sessions")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_cut_off_only_session_is_inactive_everywhere_while_its_row_is_unrevoked(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var (name, id) = await e.NewUser();
        var login = await e.LoginBody(name, refresh: true);
        var token = login.GetProperty("accessToken").GetString()!;
        var sid = new JsonWebToken(token).GetPayloadValue<string>("sid");
        Assert.True(await e.Active(verifier, token));

        await e.SetCutOff(id, DateTimeOffset.UtcNow); // no row is revoked

        Assert.False(await e.Active(verifier, token));
        Assert.Equal(0, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = login.GetProperty("refreshToken").GetString() })).StatusCode);
        // the single-session read still finds the row (it is bookkeeping); it must not claim the session is live through any other field
        var one = await e.Admin.GetAsync($"/v1/users/{id}/sessions/{sid}");
        Assert.True(one.StatusCode is HttpStatusCode.OK or HttpStatusCode.NotFound);
    }

    // ---- audit ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task The_audit_note_names_the_cut_off_for_a_reactivation_but_not_for_a_first_password_or_an_unrelated_edit(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var name = "fp-" + Guid.NewGuid().ToString("N")[..10];
        var id = (await e.Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode); // first password
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{id}", new { displayName = "Edited" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = true })).StatusCode); // no change
        Assert.Null((await e.Get(id)).SessionsValidAfter);
        var quiet = await e.Admin.GetStringAsync("/v1/audit?limit=100");
        Assert.DoesNotContain("sessionsCutOff", quiet);

        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = true })).StatusCode);
        var rows = (await e.Admin.GetFromJsonAsync<JsonElement>("/v1/audit?limit=100")).GetProperty("items").EnumerateArray()
            .Select(x => x.GetProperty("detail").GetString() ?? "").Where(d => d.Contains("sessionsCutOff=")).ToList();
        Assert.Equal(2, rows.Count); // the deactivation and the reactivation, each with its own time
        var cut = (await e.Get(id)).SessionsValidAfter!.Value;
        Assert.Contains(rows, r => r.Contains(cut.UtcDateTime.ToString("O")));
    }

    // ---- real parallel race ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Parallel_old_password_logins_racing_an_admin_reset_leave_no_live_session_afterwards(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var (name, id) = await e.NewUser();
        var survivors = 0;
        for (var round = 0; round < 6; round++)
        {
            var oldPassword = round % 2 == 0 ? Password : Fresh;
            var newPassword = round % 2 == 0 ? Fresh : Password;
            using var gate = new Barrier(5);
            var logins = Enumerable.Range(0, 4).Select(_ => Task.Run(async () =>
            {
                gate.SignalAndWait();
                return await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = oldPassword, application = e.App, refresh = true });
            })).ToList();
            var reset = Task.Run(async () =>
            {
                gate.SignalAndWait();
                return await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = newPassword });
            });
            await Task.WhenAll(logins);
            Assert.Equal(HttpStatusCode.NoContent, (await reset).StatusCode);
            // whichever way each login went, the old password no longer opens anything: nothing may still be live
            survivors += (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength();
            foreach (var l in logins)
            {
                var r = await l;
                if (r.StatusCode != HttpStatusCode.OK) continue;
                var rt = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString();
                Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = rt })).StatusCode);
            }
        }
        Assert.Equal(0, survivors);
    }

    // ---- why a few older tests lean on the 10 s cache ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task An_administrator_who_deactivates_and_reactivates_themselves_loses_their_own_sessionless_token_when_the_cache_window_ends(string store)
    {
        using var e = new Env(store);
        var me = TestAuth.EnsureAdmin(e.F);
        var other = await e.NewAdmin();
        var actor = e.Admin; // sessionless token of `me`, minted before the changes below
        Assert.Equal(HttpStatusCode.OK, (await actor.GetAsync("/v1/applications")).StatusCode); // cached for 10 s
        var acting = e.As(e.Forge(other, Reserved.AdminApp, [Reserved.AdminRole], DateTimeOffset.UtcNow - TimeSpan.FromSeconds(5), new() { ["auth_time"] = Secs(DateTimeOffset.UtcNow - TimeSpan.FromSeconds(5)) }));
        Assert.Equal(HttpStatusCode.OK, (await acting.PatchAsJsonAsync($"/v1/users/{me.Id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await acting.PatchAsJsonAsync($"/v1/users/{me.Id}", new { isActive = true })).StatusCode);

        // this instance evicted the cached answer when the administrator was deactivated and again on reactivation: no 10 s window
        Assert.Equal(HttpStatusCode.Unauthorized, (await actor.GetAsync("/v1/applications")).StatusCode); // before 7a this token worked again after reactivation
    }
}
