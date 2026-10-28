using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>QA for slice 8h: introspection, reserved admin role, If-Match variants, audit note on failure.</summary>
public class Qa8hApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Qa8hApiTests(WebApplicationFactory<Program> factory) { _factory = factory; _admin = factory.CreateAdminClient(); }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<JsonElement> Post(string url, object body)
    {
        var r = await _admin.PostAsJsonAsync(url, body);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private record W(string App, Guid AppId, Guid[] Roles, string User, Guid UserId, string Ver, string VerSecret);

    private async Task<W> World(int roleCount, int held)
    {
        var app = Unique("app");
        var appId = (await Post("/v1/applications", new { name = app })).GetProperty("id").GetGuid();
        var user = Unique("usr");
        var userId = (await Post("/v1/users", new { username = user, email = $"{user}@example.com" })).GetProperty("id").GetGuid();
        await _admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password = Password });
        var roles = new List<Guid>();
        for (var i = 0; i < roleCount; i++)
        {
            var r = (await Post($"/v1/applications/{appId}/roles", new { name = $"r{i}" })).GetProperty("id").GetGuid();
            roles.Add(r);
            if (i < held) await _admin.PutAsync($"/v1/users/{userId}/roles/{r}", null);
        }
        var ver = await Post("/v1/clients", new { name = Unique("ver"), application = appId });
        return new W(app, appId, [.. roles], user, userId, ver.GetProperty("name").GetString()!, ver.GetProperty("secret").GetString()!);
    }

    private async Task<JsonElement> Login(W w)
    {
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = w.User, password = Password, application = w.App, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private async Task<bool> Active(W w, string token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/introspect") { Content = JsonContent.Create(new { token }) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{w.Ver}:{w.VerSecret}")));
        var r = await _factory.CreateClient().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean();
    }

    private Task<HttpResponseMessage> Refresh(string t) => _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = t });

    [Fact]
    public async Task After_role_delete_introspection_and_refresh_both_fail_for_the_ended_session()
    {
        var w = await World(1, 1);
        var login = await Login(w);
        var access = login.GetProperty("accessToken").GetString()!;
        Assert.True(await Active(w, access));
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/roles/{w.Roles[0]}")).StatusCode);
        Assert.False(await Active(w, access));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(login.GetProperty("refreshToken").GetString()!)).StatusCode);
    }

    [Fact]
    public async Task A_user_who_keeps_another_role_keeps_an_active_token_and_a_working_refresh()
    {
        var w = await World(2, 2);
        var login = await Login(w);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/roles/{w.Roles[0]}")).StatusCode);
        Assert.True(await Active(w, login.GetProperty("accessToken").GetString()!));
        Assert.Equal(HttpStatusCode.OK, (await Refresh(login.GetProperty("refreshToken").GetString()!)).StatusCode);
    }

    [Fact]
    public async Task After_application_delete_the_access_token_is_not_active_for_a_surviving_verifier_and_refresh_fails()
    {
        var w = await World(1, 1);
        var other = await World(1, 1);
        var login = await Login(w);
        var access = login.GetProperty("accessToken").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/v1/applications/{w.AppId}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(login.GetProperty("refreshToken").GetString()!)).StatusCode);
        // the verifier of the deleted app is gone too, so ask through another app's verifier: still not active
        Assert.False(await Active(other, access));
    }

    [Fact]
    public async Task Role_delete_accepts_star_and_the_current_etag_and_refuses_a_stale_one_without_an_audit_count()
    {
        var w = await World(2, 1);
        var login = await Login(w);
        var role = await _admin.GetAsync($"/v1/roles/{w.Roles[0]}");
        var etag = role.Headers.ETag?.Tag;
        Assert.NotNull(etag);

        using var stale = new HttpRequestMessage(HttpMethod.Delete, $"/v1/roles/{w.Roles[0]}");
        stale.Headers.TryAddWithoutValidation("If-Match", "\"999\"");
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await _admin.SendAsync(stale)).StatusCode);
        Assert.DoesNotContain("sessionsRevoked", await _admin.GetStringAsync("/v1/audit?limit=3"));
        Assert.Equal(HttpStatusCode.OK, (await Refresh(login.GetProperty("refreshToken").GetString()!)).StatusCode);

        using var good = new HttpRequestMessage(HttpMethod.Delete, $"/v1/roles/{w.Roles[0]}");
        good.Headers.TryAddWithoutValidation("If-Match", etag);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.SendAsync(good)).StatusCode);

        using var star = new HttpRequestMessage(HttpMethod.Delete, $"/v1/roles/{w.Roles[1]}");
        star.Headers.TryAddWithoutValidation("If-Match", "*");
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.SendAsync(star)).StatusCode);

        using var gone = new HttpRequestMessage(HttpMethod.Delete, $"/v1/roles/{w.Roles[1]}");
        gone.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.SendAsync(gone)).StatusCode);
    }

    [Fact]
    public async Task Malformed_if_match_on_role_delete_is_400_and_changes_nothing()
    {
        var w = await World(1, 1);
        var login = await Login(w);
        using var bad = new HttpRequestMessage(HttpMethod.Delete, $"/v1/roles/{w.Roles[0]}");
        bad.Headers.TryAddWithoutValidation("If-Match", "banana");
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.SendAsync(bad)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(login.GetProperty("refreshToken").GetString()!)).StatusCode);
    }

    [Fact]
    public async Task The_admin_role_still_cannot_be_deleted_and_admin_sessions_survive()
    {
        var apps = await _admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().First(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await _admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        var adminRole = roles.GetProperty("items").EnumerateArray().First(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        var r = await _admin.DeleteAsync($"/v1/roles/{adminRole}");
        Assert.True((int)r.StatusCode is 403 or 409 or 400, r.StatusCode.ToString());
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync($"/v1/roles/{adminRole}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/applications?limit=1")).StatusCode); // admin client still authorised
    }
}
