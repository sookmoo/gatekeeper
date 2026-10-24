using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6f: self-service sign-in (no role in the gatekeeper application) and /v1/me.</summary>
public class Slice6fApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice6fApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<JsonElement> Post(string url, object body)
    {
        var r = await _admin.PostAsJsonAsync(url, body);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private async Task<(string Name, Guid Id)> NewUser(string? kind = null, DateTimeOffset? expiresAt = null, bool active = true)
    {
        var name = Unique("usr");
        var id = (await Post("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One", kind, expiresAt, isActive = active })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private Task<HttpResponseMessage> Login(string user, string? password = null, string app = "gatekeeper", bool refresh = true) =>
        _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = password ?? Password, application = app, refresh });

    private async Task<(HttpClient Client, string Access, string? Refresh)> SignIn(string user, bool refresh = true)
    {
        var r = await Login(user, refresh: refresh);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        var access = body.GetProperty("accessToken").GetString()!;
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return (c, access, body.TryGetProperty("refreshToken", out var rt) ? rt.GetString() : null);
    }

    /// <summary>A validly signed self-service token without a session (the login no longer issues these, so it is minted).</summary>
    private HttpClient SessionlessSelfClient(Guid id, string name)
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(_factory,
            new User(id, name, name + "@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "gatekeeper", []));
        return c;
    }

    private static string[] Roles(string jwt)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        var doc = JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement;
        return doc.GetProperty("roles").EnumerateArray().Select(r => r.GetString()!).ToArray();
    }

    // ---------------------------------------------------------------- sign-in

    [Fact]
    public async Task A_person_without_any_gatekeeper_role_gets_a_token_with_no_roles_and_a_refresh_session()
    {
        var u = await NewUser();
        var r = await Login(u.Name);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Empty(Roles(body.GetProperty("accessToken").GetString()!));
        Assert.True(body.TryGetProperty("refreshToken", out _));

        var refreshed = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = body.GetProperty("refreshToken").GetString() });
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.Empty(Roles((await refreshed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!));
    }

    [Fact]
    public async Task A_test_user_may_sign_in_but_a_shared_account_may_not()
    {
        var test = await NewUser("test", DateTimeOffset.UtcNow.AddDays(1));
        Assert.Equal(HttpStatusCode.OK, (await Login(test.Name)).StatusCode);

        var shared = await NewUser("shared");
        var refused = await Login(shared.Name);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
    }

    [Fact]
    public async Task Other_applications_still_need_a_role()
    {
        var u = await NewUser();
        var app = Unique("app");
        await Post("/v1/applications", new { name = app });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(u.Name, app: app)).StatusCode);
    }

    [Fact]
    public async Task Failures_are_one_uniform_401_whatever_the_reason()
    {
        var disabled = await NewUser(active: false);
        var good = await NewUser();
        var shared = await NewUser("shared");
        var responses = new List<(HttpStatusCode, string)>();
        foreach (var (name, password) in new[] { (disabled.Name, Password), (good.Name, "wrong password here"), ("nobody-" + Guid.NewGuid().ToString("N")[..8], Password), (shared.Name, Password) })
        {
            var r = await Login(name, password);
            responses.Add((r.StatusCode, Regex.Replace(await r.Content.ReadAsStringAsync(), "\"traceId\":\"[^\"]*\"", "")));
        }
        Assert.All(responses, x => Assert.Equal(HttpStatusCode.Unauthorized, x.Item1));
        Assert.Single(responses.Select(x => x.Item2).Distinct());
    }

    [Fact]
    public async Task Disabling_the_user_ends_the_self_token_and_the_refresh_token()
    {
        var u = await NewUser();
        var (c, _, refresh) = await SignIn(u.Name);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsJsonAsync($"/v1/users/{u.Id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh })).StatusCode);
        // Disabling ended the session, so the token is refused too (nothing was cached before: the check caches for a few seconds).
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/me")).StatusCode);
    }

    // ---------------------------------------------------------------- the self token on admin routes

    private static IEnumerable<(string Method, string Path)> Routes(WebApplicationFactory<Program> f) =>
        f.Services.GetServices<EndpointDataSource>().SelectMany(d => d.Endpoints).OfType<RouteEndpoint>()
            .SelectMany(e => (e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? ["GET"]).Select(m => (m, Concrete(e.RoutePattern.RawText!))))
            .Distinct().OrderBy(x => x.Item2).ThenBy(x => x.m);

    private static string Concrete(string pattern) => Regex.Replace(pattern, @"\{[^{}:]+(:[^{}]*)?\}", _ => Guid.NewGuid().ToString());

    private static HttpRequestMessage Request(string method, string path) =>
        new(new HttpMethod(method), path) { Content = method is "POST" or "PUT" or "PATCH" ? JsonContent.Create(new { }) : null };

    [Fact]
    public async Task A_self_token_is_403_on_every_route_that_is_not_public_or_under_v1_me()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var routes = Routes(_factory).Where(r => !(r.Path == "/v1/me" || r.Path.StartsWith("/v1/me/", StringComparison.Ordinal))
            && !r.Path.StartsWith("/v1/auth/", StringComparison.Ordinal) && r.Path is not ("/health" or "/.well-known/jwks.json") && !r.Path.StartsWith("/openapi/", StringComparison.Ordinal)).ToList();
        Assert.True(routes.Count > 30, "the route table looks too small: " + routes.Count);
        Assert.Contains(("GET", "/health/ready"), routes);
        foreach (var (method, path) in routes)
        {
            using var response = await c.SendAsync(Request(method, path));
            Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{method} {path} answered {(int)response.StatusCode} to a self token");
        }
    }

    [Fact]
    public async Task A_self_token_without_a_session_and_a_forged_admin_claim_are_also_refused_on_management_routes()
    {
        var u = await NewUser();
        var noSession = SessionlessSelfClient(u.Id, u.Name);
        // A validly signed token that claims the admin role for someone the store does not know as an administrator.
        var forged = _factory.CreateClient();
        var user = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}"));
        forged.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(_factory,
            new User(u.Id, u.Name, user.GetProperty("email").GetString()!, "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "gatekeeper", ["admin"]));
        foreach (var client in new[] { noSession, forged })
            foreach (var (method, path) in Routes(_factory).Where(r => r.Path.StartsWith("/v1/", StringComparison.Ordinal)
                         && !(r.Path == "/v1/me" || r.Path.StartsWith("/v1/me/", StringComparison.Ordinal)) && !r.Path.StartsWith("/v1/auth/", StringComparison.Ordinal)))
            {
                using var response = await client.SendAsync(Request(method, path));
                Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{method} {path} answered {(int)response.StatusCode}");
            }
    }

    [Fact]
    public async Task Tokens_of_unknown_users_are_401_everywhere_a_token_is_read()
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Token(_factory, "gatekeeper", []));
        foreach (var (method, path) in Routes(_factory).Where(r => r.Path.StartsWith("/v1/", StringComparison.Ordinal) && !r.Path.StartsWith("/v1/auth/", StringComparison.Ordinal)))
        {
            using var response = await c.SendAsync(Request(method, path));
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{method} {path} answered {(int)response.StatusCode}");
        }
    }

    [Fact]
    public void Every_route_in_the_table_is_either_public_or_guarded_by_a_known_policy()
    {
        var endpoints = _factory.Services.GetServices<EndpointDataSource>().SelectMany(d => d.Endpoints).OfType<RouteEndpoint>().ToList();
        foreach (var e in endpoints)
        {
            var path = e.RoutePattern.RawText!;
            var policies = e.Metadata.GetOrderedMetadata<IAuthorizeData>().Select(a => a.Policy).ToList();
            var anonymous = e.Metadata.GetMetadata<IAllowAnonymous>() is not null;
            if (path == "/v1/me" || path.StartsWith("/v1/me/", StringComparison.Ordinal)) Assert.Equal(["self"], policies);
            else if (path == "/health/ready") Assert.Equal(["ready"], policies);
            else if (path.StartsWith("/v1/", StringComparison.Ordinal) && !path.StartsWith("/v1/auth/", StringComparison.Ordinal)) Assert.Equal(["admin"], policies);
            else Assert.True(anonymous && policies.Count == 0, $"{path} is neither guarded by a policy nor explicitly anonymous (the fallback policy would require an administrator)");
        }
    }

    [Fact]
    public async Task A_demoted_administrator_is_403_on_management_routes_and_still_fine_on_v1_me()
    {
        var u = await NewUser();
        var appId = (await _admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray().First(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roleId = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{appId}/roles")).GetProperty("items").EnumerateArray().First(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{u.Id}/roles/{roleId}", null)).StatusCode);
        // No refresh session: removing the last role would end the sessions of the application (6a), which is a different 401.
        var (c, access, _) = await SignIn(u.Name, refresh: false);
        Assert.Equal(["admin"], Roles(access));
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/users/{u.Id}/roles/{roleId}")).StatusCode);
        // The token still claims the admin role, but the store no longer agrees.
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/v1/applications")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/v1/me")).StatusCode);
    }

    // ---------------------------------------------------------------- /v1/me

    [Fact]
    public async Task Me_shows_the_own_account_and_never_another()
    {
        var u = await NewUser();
        var other = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var me = await c.GetFromJsonAsync<JsonElement>("/v1/me");
        Assert.Equal(u.Id, me.GetProperty("id").GetGuid());
        Assert.Equal(u.Name, me.GetProperty("username").GetString());
        Assert.Equal("person", me.GetProperty("kind").GetString());
        Assert.Equal("Some One", me.GetProperty("displayName").GetString());
        Assert.DoesNotContain(other.Name, await c.GetStringAsync("/v1/me"));
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/v1/me/{other.Id}")).StatusCode);
    }

    [Fact]
    public async Task An_admin_token_works_on_v1_me_too()
    {
        var me = await _admin.GetFromJsonAsync<JsonElement>("/v1/me");
        Assert.Equal(TestAuth.AdminName, me.GetProperty("username").GetString());
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/me/sessions")).StatusCode);
    }

    [Fact]
    public async Task A_shared_accounts_token_is_refused_on_v1_me()
    {
        var shared = await NewUser("shared");
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TestAuth.Mint(_factory,
            new User(shared.Id, shared.Name, "x@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, UserKind.Shared), "gatekeeper", []));
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/v1/me/sessions")).StatusCode);
    }

    [Fact]
    public async Task A_token_for_another_audience_is_not_accepted_on_v1_me()
    {
        var u = await NewUser();
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var roleId = (await Post($"/v1/applications/{appId}/roles", new { name = "member" })).GetProperty("id").GetGuid();
        await _admin.PutAsync($"/v1/users/{u.Id}/roles/{roleId}", null);
        var login = await (await Login(u.Name, app: app)).Content.ReadFromJsonAsync<JsonElement>();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("accessToken").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/me")).StatusCode);
    }

    [Fact]
    public async Task Own_sessions_are_listed_with_the_current_one_flagged_and_other_users_sessions_never_appear()
    {
        var u = await NewUser();
        var other = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var (c2, _, _) = await SignIn(u.Name);
        await SignIn(other.Name);

        var list = await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions");
        var items = list.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(2, items.Count);
        Assert.All(items, i => Assert.Equal(u.Id, i.GetProperty("userId").GetGuid()));
        Assert.All(items, i => Assert.Equal("gatekeeper", i.GetProperty("appName").GetString()));
        Assert.Single(items, i => i.GetProperty("current").GetBoolean());
        var mine = items.Single(i => i.GetProperty("current").GetBoolean()).GetProperty("id").GetGuid();
        var viaOther = (await c2.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items").EnumerateArray().Single(i => i.GetProperty("current").GetBoolean());
        Assert.NotEqual(mine, viaOther.GetProperty("id").GetGuid());
        Assert.DoesNotContain("tokenHash", list.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refresh", list.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Revoking_an_own_session_ends_it_and_foreign_or_unknown_ids_look_identical()
    {
        var u = await NewUser();
        var other = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var (_, _, otherRefresh) = await SignIn(other.Name);
        var (_, _, victimRefresh) = await SignIn(u.Name);
        var foreignId = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{other.Id}/sessions")).GetProperty("items")[0].GetProperty("id").GetGuid();

        var foreign = await c.DeleteAsync($"/v1/me/sessions/{foreignId}");
        var unknown = await c.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(Normalise(await foreign.Content.ReadAsStringAsync(), foreignId), Normalise(await unknown.Content.ReadAsStringAsync(), Guid.Empty));
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = otherRefresh })).StatusCode); // untouched

        var own = (await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items").EnumerateArray().First(i => !i.GetProperty("current").GetBoolean()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/v1/me/sessions/{own}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/v1/me/sessions/{own}")).StatusCode); // idempotent for the owner, as on the admin route
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = victimRefresh })).StatusCode);
    }

    private static string Normalise(string body, Guid id) => Regex.Replace(body.Replace(id.ToString(), "<id>"), "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\"traceId\":\"[^\"]*\"", "<id>");

    [Fact]
    public async Task Revoking_the_current_session_ends_the_token_at_once()
    {
        var u = await NewUser();
        var (c, _, refresh) = await SignIn(u.Name);
        var current = (await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items")[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/v1/me/sessions/{current}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh })).StatusCode);
        // The cached answer for that session is dropped, so the token itself stops at once (not after the 10 s cache).
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/v1/me")).StatusCode);
    }

    [Fact]
    public async Task Revoke_all_ends_the_other_sessions_and_keeps_the_current_one()
    {
        var u = await NewUser();
        var other = await NewUser();
        var (c, _, myRefresh) = await SignIn(u.Name);
        var (_, _, r2) = await SignIn(u.Name);
        var (_, _, r3) = await SignIn(u.Name);
        var (_, _, foreign) = await SignIn(other.Name);

        var result = await c.DeleteAsync("/v1/me/sessions");
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Equal(2, (await result.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = r2 })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = r3 })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = myRefresh })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = foreign })).StatusCode);
        Assert.Single((await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items").EnumerateArray());
        Assert.Equal(0, (await (await c.DeleteAsync("/v1/me/sessions")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
    }

    [Fact]
    public async Task Revoke_all_with_a_token_that_has_no_session_ends_every_session()
    {
        var u = await NewUser();
        var (_, _, r1) = await SignIn(u.Name);
        var c = SessionlessSelfClient(u.Id, u.Name);
        Assert.Equal(1, (await (await c.DeleteAsync("/v1/me/sessions")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = r1 })).StatusCode);
    }

    [Fact]
    public async Task Self_service_writes_are_audited_with_the_user_as_actor()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var (_, _, _) = await SignIn(u.Name);
        await c.DeleteAsync("/v1/me/sessions");
        await c.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}");
        var rows = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={u.Id}&limit=50")).GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(rows, r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions" && r.GetProperty("outcome").GetString() == "success");
        var failed = Assert.Single(rows, r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions/{id}");
        Assert.Equal("failure", failed.GetProperty("outcome").GetString());
        Assert.Contains("auth.login", rows.Select(r => r.GetProperty("action").GetString()));
    }

    // ---------------------------------------------------------------- OpenAPI

    [Fact]
    public async Task OpenApi_declares_the_me_group_with_the_self_requirement()
    {
        var doc = await _factory.CreateClient().GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        var paths = doc.GetProperty("paths");
        foreach (var (path, method) in new[] { ("/v1/me", "get"), ("/v1/me/sessions", "get"), ("/v1/me/sessions", "delete"), ("/v1/me/sessions/{id}", "delete") })
        {
            var op = paths.GetProperty(path).GetProperty(method);
            Assert.Equal("self", op.GetProperty("x-gatekeeper-access").GetString());
            Assert.True(op.GetProperty("security").GetArrayLength() == 1);
        }
        Assert.Equal("admin", paths.GetProperty("/v1/applications").GetProperty("get").GetProperty("x-gatekeeper-access").GetString());
        Assert.Contains("self", doc.GetProperty("components").GetProperty("securitySchemes").GetProperty("bearer").GetProperty("description").GetString());
    }

    // ---------------------------------------------------------------- review round

    [Fact]
    public async Task A_login_without_roles_must_ask_for_a_refresh_session()
    {
        var u = await NewUser();
        var r = await Login(u.Name, refresh: false);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.DoesNotContain("accessToken", await r.Content.ReadAsStringAsync());
        Assert.Empty((await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{u.Id}/sessions")).GetProperty("items").EnumerateArray());
        // A wrong password is still the uniform 401: the 400 only follows a verified password.
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(u.Name, "wrong password here", refresh: false)).StatusCode);
    }

    [Fact]
    public async Task A_403_on_a_v1_route_is_audited_as_forbidden_with_the_user_as_actor_and_a_401_is_not()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync($"/v1/users/{u.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.DeleteAsync($"/v1/applications/{Guid.NewGuid()}")).StatusCode);
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/v1/users")).StatusCode);
        var rows = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={u.Id}&limit=50")).GetProperty("items").EnumerateArray().Where(r => r.GetProperty("outcome").GetString() == "forbidden").ToList();
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, r => r.GetProperty("action").GetString() == "GET /v1/users/{id}");
        Assert.Contains(rows, r => r.GetProperty("action").GetString() == "DELETE /v1/applications/{id}");
        Assert.DoesNotContain("anonymous", await _admin.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("GET /v1/users") + "&limit=5"));
    }

    [Fact]
    public async Task Zero_role_logins_and_refreshes_are_audited_with_roles_none_and_revoke_all_notes_what_it_kept()
    {
        var u = await NewUser();
        var (c, _, refresh) = await SignIn(u.Name);
        await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh });
        await SignIn(u.Name);
        var current = (await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items").EnumerateArray().Single(i => i.GetProperty("current").GetBoolean()).GetProperty("id").GetGuid();
        await c.DeleteAsync("/v1/me/sessions");
        var rows = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={u.Id}&limit=50")).GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(rows, r => r.GetProperty("action").GetString() == "auth.login" && r.GetProperty("detail").GetString() == "roles=none");
        Assert.Contains(rows, r => r.GetProperty("action").GetString() == "auth.refresh" && r.GetProperty("detail").GetString()!.EndsWith("; roles=none"));
        Assert.Contains(rows, r => r.GetProperty("action").GetString() == "DELETE /v1/me/sessions" && r.GetProperty("detail").GetString()!.Contains($"revoked=1; kept={current}"));
        var none = SessionlessSelfClient(u.Id, u.Name);
        await none.DeleteAsync("/v1/me/sessions");
        Assert.Contains("kept=none", await _admin.GetStringAsync($"/v1/audit?actor={u.Id}&limit=50"));
    }
}
