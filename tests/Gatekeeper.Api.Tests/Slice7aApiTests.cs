using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeeper.Api.Tests;

/// <summary>
/// Slice 7a over HTTP: the per-user session cut-off on the management API, introspection and the session lists, in memory and (when
/// GATEKEEPER_TEST_PG is set) on Postgres. Tokens are minted with explicit issue times; nothing sleeps.
/// </summary>
public class Slice7aApiTests
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

        public Env(string store, Action<IServiceCollection>? configure = null)
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
                if (configure is not null) b.ConfigureServices(configure);
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

        /// <summary>A person with a password and a role in the test application.</summary>
        public async Task<(string Name, Guid Id)> NewUser()
        {
            var name = "u-" + Guid.NewGuid().ToString("N")[..12];
            var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsync($"/v1/users/{id}/roles/{RoleId}", null)).StatusCode);
            return (name, id);
        }

        /// <summary>A second administrator (the acting one is the test admin).</summary>
        public async Task<User> NewAdmin()
        {
            var name = "adm-" + Guid.NewGuid().ToString("N")[..10];
            await Bootstrap.CreateAdminAsync(F.Services, name, name + "@example.com", Password);
            return (await F.Services.GetRequiredService<IUserRepository>().ListAsync(username: name)).Single();
        }

        public string AdminToken(User admin, DateTimeOffset issuedAt) => TestAuth.Mint(F, admin, Reserved.AdminApp, [Reserved.AdminRole], issuedAt);

        public async Task<HttpStatusCode> Manage(string token)
        {
            var c = F.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return (await c.GetAsync("/v1/applications")).StatusCode;
        }

        public async Task<string> Login(string name, string password = Password, bool refresh = false)
        {
            var r = await F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password, application = App, refresh });
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        }

        public async Task<(string Verifier, string Secret)> NewVerifier()
        {
            var v = await Post("/v1/clients", new { name = "ver-" + Guid.NewGuid().ToString("N")[..10], application = AppId });
            return (v.GetProperty("name").GetString()!, v.GetProperty("secret").GetString()!);
        }

        public async Task<JsonElement> Introspect((string Verifier, string Secret) v, string token)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token }) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{v.Verifier}:{v.Secret}")));
            var r = await F.CreateClient().SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return await r.Content.ReadFromJsonAsync<JsonElement>();
        }

        /// <summary>Puts a cut-off straight into the store (as if a change had happened at that time).</summary>
        public async Task SetCutOff(Guid userId, DateTimeOffset at)
        {
            var users = F.Services.GetRequiredService<IUserRepository>();
            await users.UpdateAsync((await users.GetAsync(userId))! with { SessionsValidAfter = at });
        }

        /// <summary>A token signed with the server's key as code before this slice issued it: no auth_time claim, and optionally no iat.</summary>
        public string LegacyUserToken(User user, DateTimeOffset? issuedAt, string audience, string[] roles, bool admin = false) =>
            new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "gatekeeper",
                Audience = audience,
                IssuedAt = issuedAt?.UtcDateTime,
                NotBefore = (issuedAt ?? DateTimeOffset.UtcNow).UtcDateTime,
                Expires = (issuedAt ?? DateTimeOffset.UtcNow).AddMinutes(15).UtcDateTime,
                TokenType = TokenService.TokenType,
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(Key) { KeyId = new TokenService(Key, new AuthOptions()).Kid }, SecurityAlgorithms.EcdsaSha256),
                Subject = new ClaimsIdentity([new Claim("sub", user.Id.ToString()), new Claim("jti", Guid.NewGuid().ToString()), new Claim("preferred_username", user.Username), new Claim("kind", "person")]),
                Claims = new Dictionary<string, object> { ["roles"] = roles },
            });

        public void Dispose()
        {
            F.Dispose();
            _db?.Dispose();
        }
    }

    private static readonly TimeSpan Past = TimeSpan.FromSeconds(10);

    // ---- sessionless management tokens ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_management_token_without_a_session_stops_after_a_password_reset(string store)
    {
        using var e = new Env(store);
        var victim = await e.NewAdmin();
        var token = e.AdminToken(victim, DateTimeOffset.UtcNow - Past);
        Assert.Equal(HttpStatusCode.OK, await e.Manage(token)); // cached as fine for a few seconds

        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{victim.Id}/password", new { password = Fresh })).StatusCode);

        // this instance evicted the cached answer at once (other instances follow after their 10 s cache)
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(token));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_management_token_without_a_session_stops_after_revoke_all_and_after_reactivation(string store)
    {
        using var e = new Env(store);
        var victim = await e.NewAdmin();
        var token = e.AdminToken(victim, DateTimeOffset.UtcNow - Past);
        Assert.Equal(HttpStatusCode.OK, await e.Manage(token));
        var revoked = await e.Admin.DeleteAsync($"/v1/users/{victim.Id}/sessions");
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(token));

        var other = await e.NewAdmin();
        var token2 = e.AdminToken(other, DateTimeOffset.UtcNow - Past);
        Assert.Equal(HttpStatusCode.OK, await e.Manage(token2));
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{other.Id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.PatchAsJsonAsync($"/v1/users/{other.Id}", new { isActive = true })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(token2)); // active again, but the token predates the pause
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_token_signed_in_after_the_cut_off_works_and_one_in_the_same_second_does_not(string store)
    {
        using var e = new Env(store);
        var admin = await e.NewAdmin();
        var cut = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(30);
        await e.SetCutOff(admin.Id, cut);
        Assert.Equal(HttpStatusCode.OK, await e.Manage(e.AdminToken(admin, cut.AddSeconds(2))));           // later second
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.AdminToken(admin, cut.AddSeconds(-2)))); // before
        var sameSecond = new DateTimeOffset(cut.UtcTicks - cut.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.AdminToken(admin, sameSecond)));          // conservative
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_token_issued_before_auth_time_existed_is_judged_by_iat_and_one_with_neither_fails_closed(string store)
    {
        using var e = new Env(store);
        var admin = await e.NewAdmin();
        var now = DateTimeOffset.UtcNow;

        // No cut-off yet: old tokens, even without iat, still work.
        Assert.Equal(HttpStatusCode.OK, await e.Manage(e.LegacyUserToken(admin, now - Past, Reserved.AdminApp, [Reserved.AdminRole])));
        Assert.Equal(HttpStatusCode.OK, await e.Manage(e.LegacyUserToken(admin, null, Reserved.AdminApp, [Reserved.AdminRole])));

        var cut = now - TimeSpan.FromSeconds(30);
        await e.SetCutOff(admin.Id, cut);
        F_Evict(e, admin.Id);
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.LegacyUserToken(admin, cut.AddSeconds(-5), Reserved.AdminApp, [Reserved.AdminRole])));
        Assert.Equal(HttpStatusCode.OK, await e.Manage(e.LegacyUserToken(admin, now - Past, Reserved.AdminApp, [Reserved.AdminRole])));
        Assert.Equal(HttpStatusCode.Unauthorized, await e.Manage(e.LegacyUserToken(admin, null, Reserved.AdminApp, [Reserved.AdminRole]))); // neither claim: closed
    }

    /// <summary>Forgets the cached access answers of the user: the stand-in for the 10 s cache window ending.</summary>
    private static void F_Evict(Env e, Guid userId) => e.F.Services.GetRequiredService<AdminAccessCheck>().Evict(userId);

    // ---- introspection ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Introspection_ends_a_token_without_a_session_after_the_change_and_reports_auth_time(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var (name, id) = await e.NewUser();
        var token = await e.Login(name);

        var before = await e.Introspect(verifier, token);
        Assert.True(before.GetProperty("active").GetBoolean());
        var authTime = before.GetProperty("auth_time").GetInt64();
        var jwt = new JsonWebToken(token);
        Assert.Equal(jwt.GetPayloadValue<long>("auth_time"), authTime);
        Assert.InRange(authTime, DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Assert.True(authTime <= before.GetProperty("iat").GetInt64());

        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh })).StatusCode);

        Assert.False((await e.Introspect(verifier, token)).GetProperty("active").GetBoolean());
        Assert.False((await e.Introspect(verifier, token)).TryGetProperty("auth_time", out _)); // nothing about a dead token
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Introspection_judges_an_old_token_by_iat_and_a_token_with_a_session_by_its_session(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var (name, id) = await e.NewUser();
        var user = (await e.F.Services.GetRequiredService<IUserRepository>().GetAsync(id))!;
        var now = DateTimeOffset.UtcNow;
        var cut = now - TimeSpan.FromSeconds(30);
        await e.SetCutOff(id, cut);

        var old = e.LegacyUserToken(user, cut.AddSeconds(-5), e.App, ["member"]);
        var recentOld = e.LegacyUserToken(user, now - TimeSpan.FromSeconds(5), e.App, ["member"]);
        Assert.False((await e.Introspect(verifier, old)).GetProperty("active").GetBoolean());
        var recent = await e.Introspect(verifier, recentOld);
        Assert.True(recent.GetProperty("active").GetBoolean());
        Assert.False(recent.TryGetProperty("auth_time", out _)); // the token has none to repeat
        Assert.False((await e.Introspect(verifier, e.LegacyUserToken(user, null, e.App, ["member"]))).GetProperty("active").GetBoolean());

        // a token with a session follows the session (a fresh sign-in after the cut-off counts) and repeats auth_time
        var login = await (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = e.App, refresh = true })).Content.ReadFromJsonAsync<JsonElement>();
        var answer = await e.Introspect(verifier, login.GetProperty("accessToken").GetString()!);
        Assert.True(answer.GetProperty("active").GetBoolean());
        Assert.True(answer.TryGetProperty("sid", out _));
        Assert.True(answer.TryGetProperty("auth_time", out _));
    }

    // ---- sessions, lists, version ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_password_reset_ends_sessions_in_every_list_and_does_not_change_the_version(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var (name, id) = await e.NewUser();
        var login = await (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = e.App, refresh = true })).Content.ReadFromJsonAsync<JsonElement>();
        var refresh = login.GetProperty("refreshToken").GetString()!;
        Assert.Equal(1, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        var etag = (await e.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag!.Tag;

        await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh });

        Assert.Equal(0, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        Assert.Equal(etag, (await e.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag!.Tag);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh })).StatusCode);

        await e.Admin.DeleteAsync($"/v1/users/{id}/sessions");
        Assert.Equal(etag, (await e.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag!.Tag); // revoke-all: still the same version
        var user = await e.Admin.GetStringAsync($"/v1/users/{id}");
        Assert.DoesNotContain("essionsValidAfter", user);
        Assert.DoesNotContain("uthenticated", await e.Admin.GetStringAsync($"/v1/users/{id}/sessions"));
        Assert.DoesNotContain("essionsValidAfter", await e.Admin.GetStringAsync("/v1/users"));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Deactivation_bumps_the_version_once_and_the_audit_note_records_the_cut_off(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var (_, id) = await e.NewUser();
        var v1 = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}")).GetProperty("version").GetInt64();
        var res = await e.Admin.PatchAsJsonAsync($"/v1/users/{id}", new { isActive = false });
        Assert.Equal(v1 + 1, (await res.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("version").GetInt64());
        await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh });
        await e.Admin.DeleteAsync($"/v1/users/{id}/sessions");
        var rows = (await e.Admin.GetFromJsonAsync<JsonElement>("/v1/audit?limit=50")).GetProperty("items").EnumerateArray()
            .Select(x => x.GetProperty("action").GetString() + " | " + x.GetProperty("detail").GetString()).ToList();
        Assert.Contains(rows, r => r.StartsWith("PATCH /v1/users/{id}") && r.Contains("sessionsCutOff="));
        Assert.Contains(rows, r => r.StartsWith("PUT /v1/users/{id}/password") && r.Contains("sessionsCutOff="));
        Assert.Contains(rows, r => r.StartsWith("DELETE /v1/users/{id}/sessions") && r.Contains("sessionsCutOff="));
        Assert.DoesNotContain(Fresh, string.Join('\n', rows));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_first_password_leaves_no_cut_off_so_a_sessionless_token_works_at_once(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var (name, _) = await e.NewUser();
        var answer = await e.Introspect(verifier, await e.Login(name)); // the token is from the same second as the first password
        Assert.True(answer.GetProperty("active").GetBoolean());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task An_own_password_change_keeps_exactly_the_current_session_and_records_the_cut_off(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var (name, id) = await e.NewUser();
        async Task<(HttpClient C, string Refresh)> SignIn()
        {
            var r = await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
            var body = await r.Content.ReadFromJsonAsync<JsonElement>();
            var c = e.F.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("accessToken").GetString());
            return (c, body.GetProperty("refreshToken").GetString()!);
        }
        var (current, currentRefresh) = await SignIn();
        var (other, otherRefresh) = await SignIn();
        var etag = (await e.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag!.Tag;

        var change = await current.PutAsJsonAsync("/v1/me/password", new { currentPassword = Password, newPassword = Fresh });
        Assert.Equal(HttpStatusCode.NoContent, change.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await current.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = currentRefresh })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = otherRefresh })).StatusCode);
        var own = (await current.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items");
        Assert.Equal(1, own.GetArrayLength());
        Assert.True(own[0].GetProperty("current").GetBoolean());
        Assert.Equal(etag, (await e.Admin.GetAsync($"/v1/users/{id}")).Headers.ETag!.Tag);
        var rows = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={id}&limit=50")).GetProperty("items").EnumerateArray()
            .Select(x => x.GetProperty("detail").GetString()).ToList();
        Assert.Contains(rows, r => r!.Contains("sessionsRevoked=1") && r.Contains("sessionsCutOff="));
        // and the new password signs in, the old one does not
        Assert.Equal(HttpStatusCode.OK, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Fresh, application = e.App, refresh = true })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = e.App, refresh = true })).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task The_users_own_end_my_other_sessions_stays_per_session_and_does_not_cut_off_tokens(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var (name, id) = await e.NewUser();
        async Task<HttpClient> SignIn()
        {
            var r = await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
            var c = e.F.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
            return c;
        }
        var current = await SignIn();
        var other = await SignIn();
        Assert.Equal(HttpStatusCode.OK, (await current.DeleteAsync("/v1/me/sessions")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await current.GetAsync("/v1/me")).StatusCode);
        Assert.Null((await e.F.Services.GetRequiredService<IUserRepository>().GetAsync(id))!.SessionsValidAfter);
    }

    // ---- races at the endpoint ----

    private sealed class RaceCredentials(ICredentialRepository inner) : ICredentialRepository
    {
        public Func<Task>? AfterGetHash;
        public Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default) => inner.SetAsync(userId, hash, at, cutOffAt, ct);
        public Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default) =>
            inner.ReplaceHashAsync(userId, expectedHash, newHash, at, cutOffAt, keepSession, ct);
        public async Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default)
        {
            var hash = await inner.GetHashAsync(userId, ct);
            if (AfterGetHash is { } hook) { AfterGetHash = null; await hook(); }
            return hash;
        }
    }

    [Fact]
    public async Task A_login_that_verified_the_old_password_while_the_admin_reset_it_is_401_raced_and_leaves_no_live_session()
    {
        RaceCredentials? race = null;
        using var e = new Env("mem", s => s.AddSingleton<ICredentialRepository>(sp => race = new RaceCredentials(new InMemoryCredentialRepository(sp.GetRequiredService<InMemoryStore>()))));
        await e.SeedApp();
        var (name, id) = await e.NewUser();
        race!.AfterGetHash = async () => Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh })).StatusCode);

        var login = await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = e.App, refresh = true });

        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Equal(0, (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions")).GetProperty("items").GetArrayLength());
        var details = (await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={id}&limit=20")).GetProperty("items").EnumerateArray().Select(x => x.GetProperty("detail").GetString()).ToList();
        Assert.Contains("raced", details);
        // the new password works afterwards
        Assert.Equal(HttpStatusCode.OK, (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Fresh, application = e.App, refresh = true })).StatusCode);
    }

    [Fact]
    public async Task A_login_without_a_session_that_raced_the_reset_is_refused_at_the_first_use()
    {
        RaceCredentials? race = null;
        using var e = new Env("mem", s => s.AddSingleton<ICredentialRepository>(sp => race = new RaceCredentials(new InMemoryCredentialRepository(sp.GetRequiredService<InMemoryStore>()))));
        await e.SeedApp();
        var verifier = await e.NewVerifier();
        var (name, id) = await e.NewUser();
        race!.AfterGetHash = async () => await e.Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Fresh });

        var login = await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = e.App, refresh = false });

        // A token without a session cannot be taken back at the insert; it is issued but the cut-off refuses it wherever it is checked.
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        Assert.False((await e.Introspect(verifier, token)).GetProperty("active").GetBoolean());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task A_session_the_cut_off_ended_shows_as_revoked_when_fetched_by_id(string store)
    {
        using var e = new Env(store);
        await e.SeedApp();
        var (name, id) = await e.NewUser();
        var login = await (await e.F.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = e.App, refresh = true })).Content.ReadFromJsonAsync<JsonElement>();
        var sid = new JsonWebToken(login.GetProperty("accessToken").GetString()!).GetPayloadValue<string>("sid");
        // the cut-off alone (as after a crash before the row revoke): put it in the store without touching the row
        await e.SetCutOff(id, DateTimeOffset.UtcNow.AddSeconds(1));
        var one = await e.Admin.GetFromJsonAsync<JsonElement>($"/v1/users/{id}/sessions/{sid}");
        Assert.NotEqual(JsonValueKind.Null, one.GetProperty("revokedAt").ValueKind);
    }
}
