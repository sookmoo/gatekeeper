using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA of slice 6f: gaps left by Slice6fApiTests.</summary>
public class Slice6fQaApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice6fQaApiTests(WebApplicationFactory<Program> factory) { _factory = factory; _admin = factory.CreateAdminClient(); }

    private async Task<(string Name, Guid Id)> NewUser(string? kind = null, DateTimeOffset? expiresAt = null)
    {
        var name = $"qa-{Guid.NewGuid():N}"[..18];
        var r = await _admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Q A", kind, expiresAt });
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private async Task<(HttpClient C, string? Refresh, string Access)> SignIn(string user, string app = "gatekeeper")
    {
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = user, password = Password, application = app, refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var b = await r.Content.ReadFromJsonAsync<JsonElement>();
        var c = _factory.CreateClient();
        var access = b.GetProperty("accessToken").GetString()!;
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return (c, b.GetProperty("refreshToken").GetString(), access);
    }

    [Fact]
    public async Task Application_name_in_another_case_still_yields_a_working_self_token()
    {
        var u = await NewUser();
        var r = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = u.Name, password = Password, application = "GateKeeper", refresh = true });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/v1/users")).StatusCode);
    }

    [Fact]
    public async Task Refresh_stops_when_the_user_becomes_a_shared_account()
    {
        var u = await NewUser();
        var (c, refresh, _) = await SignIn(u.Name);
        var patch = await _admin.SendAsync(new HttpRequestMessage(HttpMethod.Patch, $"/v1/users/{u.Id}") { Content = JsonContent.Create(new { kind = "shared" }) });
        Assert.True(patch.IsSuccessStatusCode, await patch.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh })).StatusCode);
        var me = await c.GetAsync("/v1/me");
        Assert.True(me.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized, "shared token on /v1/me: " + (int)me.StatusCode);
    }

    [Fact]
    public async Task Me_answers_without_slash_and_with_slash_and_is_no_store_and_anonymous_is_401()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        foreach (var path in new[] { "/v1/me", "/v1/me/" })
        {
            var r = await c.GetAsync(path);
            Assert.True(r.StatusCode == HttpStatusCode.OK, $"{path} {(int)r.StatusCode}");
            Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
        }
        var anon = _factory.CreateClient();
        foreach (var p in new[] { "/v1/me", "/v1/me/sessions" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync(p)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.DeleteAsync("/v1/me/sessions")).StatusCode);
    }

    [Fact]
    public async Task Me_body_has_no_secrets_and_no_roles_or_ids_of_others()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var text = await c.GetStringAsync("/v1/me");
        foreach (var bad in new[] { "hash", "password", "version", "isActive" })
            Assert.DoesNotContain(bad, text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Session_listing_validates_paging_and_hides_ended_sessions()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        await SignIn(u.Name);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/v1/me/sessions?limit=0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/v1/me/sessions?cursor=garbage")).StatusCode);
        var page = await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions?limit=1");
        Assert.Single(page.GetProperty("items").EnumerateArray());
        await c.DeleteAsync("/v1/me/sessions");
        var after = await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions");
        Assert.Single(after.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Foreign_session_id_404_has_same_headers_and_body_shape_as_unknown_and_malformed_id_is_not_a_different_oracle()
    {
        var u = await NewUser();
        var other = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        await SignIn(other.Name);
        var foreignId = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{other.Id}/sessions")).GetProperty("items")[0].GetProperty("id").GetGuid();
        var a = await c.DeleteAsync($"/v1/me/sessions/{foreignId}");
        var b = await c.DeleteAsync($"/v1/me/sessions/{Guid.NewGuid()}");
        Assert.Equal(a.StatusCode, b.StatusCode);
        Assert.Equal(a.Content.Headers.ContentType, b.Content.Headers.ContentType);
        var ja = await a.Content.ReadFromJsonAsync<JsonElement>(); var jb = await b.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ja.GetProperty("title").GetString(), jb.GetProperty("title").GetString());
        Assert.Equal(ja.GetProperty("status").GetInt32(), jb.GetProperty("status").GetInt32());
        // The foreign session is still alive for its owner.
        Assert.Equal(1, (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{other.Id}/sessions")).GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync("/v1/me/sessions/not-a-guid")).StatusCode);
    }

    [Fact]
    public async Task Self_token_cannot_read_or_revoke_through_admin_session_routes()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var id = (await c.GetFromJsonAsync<JsonElement>("/v1/me/sessions")).GetProperty("items")[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync($"/v1/users/{u.Id}/sessions")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.DeleteAsync($"/v1/users/{u.Id}/sessions/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync($"/v1/users/{u.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/v1/audit")).StatusCode);
    }

    [Fact]
    public async Task A_403_for_a_self_token_leaks_nothing_about_the_resource()
    {
        var u = await NewUser();
        var (c, _, _) = await SignIn(u.Name);
        var existing = await c.GetAsync($"/v1/users/{u.Id}");
        var missing = await c.GetAsync($"/v1/users/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.Forbidden, existing.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, missing.StatusCode);
        Assert.Equal((await existing.Content.ReadAsStringAsync()).Length, (await missing.Content.ReadAsStringAsync()).Length);
    }
}
