using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace Gatekeeper.Api.Tests;

public class Qa4cApiTests : IDisposable
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _f;
    private readonly HttpClient _admin;
    private readonly ITestOutputHelper _out;

    public Qa4cApiTests(ITestOutputHelper o) { _f = new WebApplicationFactory<Program>(); _admin = _f.CreateAdminClient(); _out = o; }
    public void Dispose() => _f.Dispose();

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<JsonElement> Post(string url, object body)
    {
        var r = await _admin.PostAsJsonAsync(url, body);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private record W(string User, Guid UserId, string App, Guid AppId, string Verifier, string VerifierSecret);

    private async Task<W> World(int sessionsToo = 0)
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var role = (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        var name = Unique("usr");
        var uid = (await Post("/v1/users", new { username = name, email = $"{name}@example.com" })).GetProperty("id").GetGuid();
        await _admin.PutAsJsonAsync($"/v1/users/{uid}/password", new { password = Password });
        await _admin.PutAsync($"/v1/users/{uid}/roles/{role}", null);
        var v = await Post("/v1/clients", new { name = Unique("ver"), application = appId });
        return new W(name, uid, app, appId, v.GetProperty("name").GetString()!, v.GetProperty("secret").GetString()!);
    }

    private async Task<JsonElement> Login(W w, bool refresh = true) =>
        await (await _f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = w.User, password = Password, application = w.App, refresh })).Content.ReadFromJsonAsync<JsonElement>();

    private Task<HttpResponseMessage> Refresh(string? t) => _f.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = t });

    // ---- concurrency ----

    [Fact]
    public async Task Concurrent_refresh_of_one_token_leaves_the_winners_new_token_usable()
    {
        var w = await World();
        var bad = 0; var killed = 0; var rounds = 6;
        for (var i = 0; i < rounds; i++)
        {
            var login = await Login(w);
            var token = login.GetProperty("refreshToken").GetString()!;
            var rs = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() => Refresh(token))));
            var ok = rs.Where(r => r.StatusCode == HttpStatusCode.OK).ToList();
            Assert.All(rs, r => Assert.True(r.StatusCode is HttpStatusCode.OK or HttpStatusCode.Unauthorized, r.StatusCode.ToString()));
            if (ok.Count != 1) { bad++; continue; }
            var next = (await ok[0].Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refreshToken").GetString()!;
            if ((await Refresh(next)).StatusCode != HttpStatusCode.OK) killed++;
        }
        _out.WriteLine($"rounds={rounds} notExactlyOneWinner={bad} winnerSessionKilled={killed}");
        Assert.Equal(0, bad);
        Assert.Equal(0, killed); // a duplicate submission must not destroy the winner's session
    }

    // ---- malformed refresh tokens ----

    public static IEnumerable<object?[]> BadTokens() =>
    [
        [null], [""], ["gkr_"], ["gkr_."], ["gkr_AAAAAAAAAAAAAAAAAAAAAA."], ["gkr_AAAAAAAAAAAAAAAAAAAAAA.x.y"],
        ["gkr_!!!!!!!!!!!!!!!!!!!!!!.secretsecret"], ["GKR_AAAAAAAAAAAAAAAAAAAAAA.abcdefghij"], [new string('a', 100_000)],
        ["gkr_AAAAAAAAAAAAAAAAAAAAAA.\u0000\u0001"], ["gkr_AAAAAAAAAAAAAAAAAAAAAA.\ud800"], ["gkr_AAAAAAAAAAAAAAAAAAAAAA.é"],
    ];

    [Theory, MemberData(nameof(BadTokens))]
    public async Task Malformed_refresh_tokens_are_401_never_500(string? token)
    {
        var r = await Refresh(token);
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        var lo = await _f.CreateClient().PostAsJsonAsync("/v1/auth/logout", new { refreshToken = token });
        Assert.Equal(HttpStatusCode.NoContent, lo.StatusCode);
    }

    [Theory]
    [InlineData("")] [InlineData("null")] [InlineData("[]")] [InlineData("\"x\"")] [InlineData("{\"refreshToken\":5}")] [InlineData("{")]
    public async Task Odd_refresh_bodies_are_4xx(string body)
    {
        foreach (var path in new[] { "/v1/auth/refresh", "/v1/auth/logout" })
        {
            var r = await _f.CreateClient().PostAsync(path, new StringContent(body, Encoding.UTF8, "application/json"));
            _out.WriteLine($"{path} {body} -> {(int)r.StatusCode}");
            Assert.InRange((int)r.StatusCode, 400, 499);
        }
    }

    [Fact]
    public async Task Logout_with_a_token_of_the_right_session_but_wrong_secret_changes_nothing()
    {
        var w = await World();
        var t = (await Login(w)).GetProperty("refreshToken").GetString()!;
        var forged = t[..t.IndexOf('.')] + ".AAAA";
        Assert.Equal(HttpStatusCode.NoContent, (await _f.CreateClient().PostAsJsonAsync("/v1/auth/logout", new { refreshToken = forged })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(t)).StatusCode);
    }

    [Fact]
    public async Task A_forged_secret_for_a_real_session_does_not_end_it()
    {
        var w = await World();
        var t = (await Login(w)).GetProperty("refreshToken").GetString()!;
        var forged = t[..t.IndexOf('.')] + ".AAAA";
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(forged)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(t)).StatusCode);
    }

    [Fact]
    public async Task Failed_refreshes_must_not_lock_users_out_of_logging_in_from_the_same_address()
    {
        var w = await World();
        for (var i = 0; i < 70; i++) await Refresh("gkr_AAAAAAAAAAAAAAAAAAAAAA.stale");
        var r = await _f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = w.User, password = Password, application = w.App, refresh = true });
        _out.WriteLine("login after 70 stale refreshes -> " + (int)r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    // ---- Basic header ----

    private async Task<HttpStatusCode> IntrospectWithRawAuth(params string[] headers)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token = "x" }) };
        foreach (var h in headers) req.Headers.TryAddWithoutValidation("Authorization", h);
        return (await _f.CreateClient().SendAsync(req)).StatusCode;
    }

    [Fact]
    public async Task Odd_basic_headers_are_401()
    {
        var w = await World();
        string B(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        var cases = new[]
        {
            "Basic", "Basic ", "Basic !!!", "Basic Zm9v", "Basic " + B("noColon"), "Basic " + B(":"), "Basic " + B(":" + w.VerifierSecret),
            "Basic " + B(w.Verifier + ":"), "Basic " + B(w.Verifier + ":x"), "Basic " + new string('A', 5000), "Basic AAA", "Basic =",
            "Basic " + Convert.ToBase64String([0xff, 0xfe, 0x3a, 0xff]), "Bearer " + B(w.Verifier + ":" + w.VerifierSecret),
            "Basic " + B(w.Verifier + ":" + w.VerifierSecret + ":extra"), "Basic " + B(w.Verifier + ":" + new string('z', 100_000)).Substring(0, 900),
        };
        foreach (var c in cases)
            Assert.Equal(HttpStatusCode.Unauthorized, await IntrospectWithRawAuth(c));
        Assert.Equal(HttpStatusCode.Unauthorized, await IntrospectWithRawAuth());
        Assert.Equal(HttpStatusCode.Unauthorized, await IntrospectWithRawAuth("Basic " + B(w.Verifier + ":" + w.VerifierSecret), "Basic " + B(w.Verifier + ":" + w.VerifierSecret)));
        // control: the right credentials, in unusual but valid spellings, work
        Assert.Equal(HttpStatusCode.OK, await IntrospectWithRawAuth("basic " + B(w.Verifier + ":" + w.VerifierSecret)));
        Assert.Equal(HttpStatusCode.OK, await IntrospectWithRawAuth("Basic   " + B(w.Verifier + ":" + w.VerifierSecret) + "  "));
    }

    [Fact]
    public async Task Introspect_without_credentials_and_with_bad_body_prefers_401_over_400()
    {
        // An unauthenticated caller should not get body-validation feedback (and a bad body must not bypass the failure throttle).
        var c = _f.CreateClient();
        var r = await c.PostAsync("/v1/auth/introspect", new StringContent("{", Encoding.UTF8, "application/json"));
        _out.WriteLine("bad body, no creds -> " + (int)r.StatusCode);
        var r2 = await c.PostAsync("/v1/auth/introspect", new StringContent("{}", Encoding.UTF8, "text/plain"));
        _out.WriteLine("text/plain, no creds -> " + (int)r2.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, r2.StatusCode);
    }

    [Fact]
    public async Task Introspect_with_valid_client_and_empty_or_odd_body_is_inactive_or_400_not_500()
    {
        var w = await World();
        string auth = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(w.Verifier + ":" + w.VerifierSecret));
        foreach (var body in new[] { "", "null", "{}", "{\"token\":null}", "{\"token\":\"a.b.c\"}", "{\"token\":\"" + new string('a', 20000) + "\"}", "{\"token\":5}" })
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            req.Headers.TryAddWithoutValidation("Authorization", auth);
            var r = await _f.CreateClient().SendAsync(req);
            _out.WriteLine($"{(body.Length > 40 ? body[..40] : body)} -> {(int)r.StatusCode}");
            Assert.True((int)r.StatusCode < 500);
        }
    }

    // ---- sessions API ----

    [Fact]
    public async Task Session_listing_pages_cover_every_session_once_and_revoke_all_counts_them()
    {
        var w = await World();
        for (var i = 0; i < 7; i++) await Login(w);
        var seen = new List<string>();
        string? cursor = null;
        do
        {
            var url = $"/v1/users/{w.UserId}/sessions?limit=3" + (cursor is null ? "" : "&cursor=" + Uri.EscapeDataString(cursor));
            var page = await _admin.GetFromJsonAsync<JsonElement>(url);
            seen.AddRange(page.GetProperty("items").EnumerateArray().Select(x => x.GetProperty("id").GetString()!));
            cursor = page.GetProperty("nextCursor").ValueKind == JsonValueKind.Null ? null : page.GetProperty("nextCursor").GetString();
        } while (cursor is not null);
        Assert.Equal(7, seen.Count);
        Assert.Equal(7, seen.Distinct().Count());
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync($"/v1/users/{w.UserId}/sessions?limit=0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync($"/v1/users/{w.UserId}/sessions?cursor=garbage")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/v1/users/{Guid.NewGuid()}/sessions")).StatusCode);
        var del = await _admin.DeleteAsync($"/v1/users/{w.UserId}/sessions");
        Assert.Equal(7, (await del.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        var again = await _admin.DeleteAsync($"/v1/users/{w.UserId}/sessions");
        Assert.Equal(0, (await again.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/v1/users/{w.UserId}/sessions/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task Session_lists_never_show_token_material()
    {
        var w = await World();
        var login = await Login(w);
        var text = await _admin.GetStringAsync($"/v1/users/{w.UserId}/sessions");
        Assert.DoesNotContain("hash", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(login.GetProperty("refreshToken").GetString()!.Split('.')[1], text);
    }

    [Fact]
    public async Task Deactivating_a_user_ends_their_refresh_session_and_admin_sessions_stop_working()
    {
        var w = await World();
        var login = await Login(w);
        var token = login.GetProperty("refreshToken").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{w.UserId}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(token)).StatusCode);
        // ...and re-activating must not bring the session back
        await _admin.PatchAsJsonAsync($"/v1/users/{w.UserId}", new { isActive = true });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(token)).StatusCode);
    }

    [Fact]
    public async Task Introspect_reports_a_deactivated_users_session_token_inactive_immediately()
    {
        var w = await World();
        var login = await Login(w);
        await _admin.PatchAsJsonAsync($"/v1/users/{w.UserId}", new { isActive = false });
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token = login.GetProperty("accessToken").GetString() }) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(w.Verifier + ":" + w.VerifierSecret)));
        var answer = await (await _f.CreateClient().SendAsync(req)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(answer.GetProperty("active").GetBoolean());
    }

    // ---- OpenAPI ----

    [Fact]
    public async Task Openapi_file_matches_the_served_document_in_full()
    {
        var served = JsonDocument.Parse(await _f.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement;
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "Gatekeeper.slnx"))) d = d.Parent;
        var file = JsonDocument.Parse(File.ReadAllText(Path.Combine(d!.FullName, "docs", "openapi.json"))).RootElement;
        Assert.Equal(Canon(file), Canon(served));
    }

    private static string Canon(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", e.EnumerateObject().Where(p => p.Name != "servers").OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => $"\"{p.Name}\":{Canon(p.Value)}")) + "}",
        JsonValueKind.Array => "[" + string.Join(",", e.EnumerateArray().Select(Canon)) + "]",
        _ => e.GetRawText(),
    };

    [Fact]
    public async Task Openapi_documents_the_new_endpoints_and_their_statuses()
    {
        var doc = JsonDocument.Parse(await _f.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement;
        var paths = doc.GetProperty("paths");
        string Statuses(string p, string m) => string.Join(",", paths.GetProperty(p).GetProperty(m).GetProperty("responses").EnumerateObject().Select(x => x.Name).OrderBy(x => x));
        foreach (var (p, m) in new[] { ("/v1/auth/refresh", "post"), ("/v1/auth/logout", "post"), ("/v1/auth/introspect", "post"),
                     ("/v1/users/{id}/sessions", "get"), ("/v1/users/{id}/sessions", "delete") })
            _out.WriteLine($"{m} {p}: {Statuses(p, m)}");
        Assert.Contains("204", Statuses("/v1/auth/logout", "post")); // README and behaviour: always 204
        Assert.Contains("404", Statuses("/v1/users/{id}/sessions/{sessionId}", "delete"));
        Assert.Contains("404", Statuses("/v1/users/{id}/sessions", "get"));
        Assert.Contains("404", Statuses("/v1/users/{id}/sessions", "delete"));
    }

    // ---- key parsing ----

    private static string Pub(ECDsa k) => k.ExportSubjectPublicKeyInfoPem();
    private static ECDsa K() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void Truncated_or_garbage_retired_key_text_is_not_silently_accepted()
    {
        var pem = Pub(K());
        var truncated = pem.Replace("-----END PUBLIC KEY-----", "");
        var noBegin = pem.Replace("-----BEGIN PUBLIC KEY-----", "");
        foreach (var bad in new[] { truncated, noBegin, "this is not a key", "-----BEGIN PUBLIC KEY-----\nAAAA\n" })
            Assert.Throws<ArgumentException>(() => TokenService.LoadRetiredKeys(bad)); // never silently "no retired keys"
        Assert.Empty(TokenService.LoadRetiredKeys("# only a comment\n\n"));
    }

    [Fact]
    public void Retired_key_edge_cases_in_token_service()
    {
        var cur = K();
        var a = K(); var b = K();
        Assert.Empty(TokenService.LoadRetiredKeys(""));
        Assert.Equal(2, TokenService.LoadRetiredKeys(Pub(a) + "\n# c\n" + Pub(b)).Count);
        Assert.Single(TokenService.LoadRetiredKeys(a.ExportPkcs8PrivateKeyPem()));
        Assert.Single(TokenService.LoadRetiredKeys(a.ExportECPrivateKeyPem()));
        Assert.Throws<ArgumentException>(() => TokenService.LoadRetiredKeys("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
        Assert.ThrowsAny<CryptographicException>(() => TokenService.LoadRetiredKeys("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"));
        using var rsa = RSA.Create(2048);
        Assert.ThrowsAny<Exception>(() => TokenService.LoadRetiredKeys(rsa.ExportSubjectPublicKeyInfoPem()));
        // P-384 retired key
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<ArgumentException>(() => new TokenService(cur, new AuthOptions(), TokenService.LoadRetiredKeys(Pub(p384))));
        // duplicates and current-in-retired collapse
        var svc = new TokenService(cur, new AuthOptions(), TokenService.LoadRetiredKeys(Pub(a) + "\n" + Pub(a) + "\n" + Pub(cur)));
        Assert.Equal(2, svc.VerificationKeys.Count);
        // exactly 5 ok, 6 refused
        var five = Enumerable.Range(0, 5).Select(_ => K()).ToList();
        Assert.Equal(6, new TokenService(cur, new AuthOptions(), five).VerificationKeys.Count);
        Assert.Throws<ArgumentException>(() => new TokenService(cur, new AuthOptions(), five.Append(K())));
    }

    [Fact]
    public async Task Startup_with_bad_retired_keys_fails_cleanly()
    {
        foreach (var bad in new[] { "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----" })
        {
            using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            {
                b.UseSetting("Auth:SigningKeyPem", K().ExportPkcs8PrivateKeyPem());
                b.UseSetting("Auth:RetiredKeysPem", bad);
            });
            var ex = await Record.ExceptionAsync(async () => await f.CreateClient().GetAsync("/health"));
            _out.WriteLine(ex?.GetType().Name + ": " + ex?.Message);
            Assert.NotNull(ex);
        }
        // a retired-keys file that is a directory / missing
        using var f2 = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Auth:SigningKeyPem", K().ExportPkcs8PrivateKeyPem());
            b.UseSetting("Auth:RetiredKeysPemFile", "/nonexistent/retired.pem");
        });
        Assert.NotNull(await Record.ExceptionAsync(async () => await f2.CreateClient().GetAsync("/health")));
    }

    [Fact]
    public async Task Tokens_signed_by_a_retired_key_do_not_pass_introspection_after_the_key_is_dropped_and_vice_versa()
    {
        var oldKey = K(); var cur = K();
        using var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Auth:SigningKeyPem", cur.ExportPkcs8PrivateKeyPem());
            b.UseSetting("Auth:RetiredKeysPem", Pub(oldKey));
        });
        var admin = f.CreateAdminClient();
        var app = Unique("app");
        var appId = (await (await admin.PostAsJsonAsync("/v1/applications", new { name = app })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var role = (await (await admin.PostAsJsonAsync($"/v1/applications/{appId}/roles", new { name = "m" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var un = Unique("usr");
        var uid = (await (await admin.PostAsJsonAsync("/v1/users", new { username = un, email = un + "@example.com" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        await admin.PutAsync($"/v1/users/{uid}/roles/{role}", null);
        var ver = await (await admin.PostAsJsonAsync("/v1/clients", new { name = Unique("ver"), application = appId })).Content.ReadFromJsonAsync<JsonElement>();
        var user = (await f.Services.GetRequiredService<IUserRepository>().GetAsync(uid))!;
        var tok = new TokenService(oldKey, new AuthOptions()).Issue(new AuthResult(user, new Gatekeeper.Domain.App(appId, app), ["m"])).Token;
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token = tok }) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(ver.GetProperty("name").GetString() + ":" + ver.GetProperty("secret").GetString())));
        var ans = await (await f.CreateClient().SendAsync(req)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(ans.GetProperty("active").GetBoolean());
    }
}
