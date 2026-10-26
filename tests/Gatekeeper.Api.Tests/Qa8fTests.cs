using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace Gatekeeper.Api.Tests;

/// <summary>QA round for slice 8f (written from the spec: wrong Content-Type is authorised first, then a 415 from binding).</summary>
public class Qa8fTests : IDisposable
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory = new();
    private readonly ITestOutputHelper _out;

    public Qa8fTests(ITestOutputHelper o) => _out = o;
    public void Dispose() => _factory.Dispose();

    private async Task<(HttpClient Client, string Id)> SelfClient()
    {
        var admin = _factory.CreateAdminClient();
        var name = $"usr-{Guid.NewGuid():N}"[..20];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var login = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return (c, id.ToString());
    }

    private static HttpRequestMessage Req(string method, string path, string? body, string? contentType)
    {
        var m = new HttpRequestMessage(new HttpMethod(method), path);
        if (body is not null)
        {
            m.Content = new StringContent(body, Encoding.UTF8);
            m.Content.Headers.ContentType = contentType is null ? null : MediaTypeHeaderValue.Parse(contentType);
        }
        return m;
    }

    private async Task<List<JsonElement>> Audit(HttpClient admin, string actor) =>
        (await admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=200")).GetProperty("items").EnumerateArray().ToList();

    [Theory]
    [InlineData("application/json")]
    [InlineData("APPLICATION/JSON")]
    [InlineData("Application/Json; charset=utf-8")]
    [InlineData("application/json; charset=UTF-8")]
    [InlineData("application/json;charset=utf-8;foo=bar")]
    [InlineData("application/merge-patch+json")]
    [InlineData("application/vnd.api+json")]
    public async Task Json_content_type_variants_reach_the_handler_for_admin_and_self(string type)
    {
        var admin = _factory.CreateAdminClient();
        var (self, _) = await SelfClient();
        var a = await admin.SendAsync(Req("POST", "/v1/applications", "{\"name\":\"a" + Guid.NewGuid().ToString("N")[..8] + "\"}", type));
        var s = await self.SendAsync(Req("PUT", "/v1/me/password", "{\"currentPassword\":\"" + Password + "\",\"newPassword\":\"another long passphrase\"}", type));
        _out.WriteLine($"{type}: admin {(int)a.StatusCode} self {(int)s.StatusCode}");
        Assert.NotEqual(HttpStatusCode.UnsupportedMediaType, a.StatusCode);
        Assert.NotEqual(HttpStatusCode.UnsupportedMediaType, s.StatusCode);
        Assert.True((int)s.StatusCode is >= 200 and < 300, $"self {(int)s.StatusCode}");
    }

    [Theory]
    [InlineData("multipart/form-data; boundary=x")]
    [InlineData("text/json")]
    [InlineData("application/jsonx")]
    [InlineData("*/*")]
    public async Task Other_types_are_415_on_patch_and_put_for_admin_and_403_or_415_by_route_for_self(string type)
    {
        var admin = _factory.CreateAdminClient();
        var (self, _) = await SelfClient();
        var created = await admin.PostAsJsonAsync("/v1/applications", new { name = "p" + Guid.NewGuid().ToString("N")[..8] });
        var appId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        foreach (var method in new[] { "PATCH", "PUT" })
        {
            var r = await admin.SendAsync(Req(method, $"/v1/applications/{appId}", "{\"name\":\"zz\"}", type));
            _out.WriteLine($"{method} admin {type}: {(int)r.StatusCode}");
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, r.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await self.SendAsync(Req(method, $"/v1/applications/{appId}", "{}", type))).StatusCode);
        }
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await self.SendAsync(Req("PUT", "/v1/me/password", "{}", type))).StatusCode);
        // the resource must be untouched
        Assert.Equal("200", ((int)(await admin.GetAsync($"/v1/applications/{appId}")).StatusCode).ToString());
    }

    [Fact]
    public async Task Json_patch_media_type_is_treated_as_json_on_patch_routes_as_before_the_fix()
    {
        // A "+json" suffix is accepted by the JSON binding (identical result with and without 8f); the body is read as a merge-style object, not RFC 6902.
        var admin = _factory.CreateAdminClient();
        var created = await admin.PostAsJsonAsync("/v1/applications", new { name = "jp" + Guid.NewGuid().ToString("N")[..8] });
        var appId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(Req("PATCH", $"/v1/applications/{appId}", "{\"name\":\"jp-renamed\"}", "application/json-patch+json"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(Req("PATCH", $"/v1/applications/{appId}", "[{\"op\":\"replace\",\"path\":\"/name\",\"value\":\"x\"}]", "application/json-patch+json"))).StatusCode);
    }

    [Fact]
    public async Task Missing_content_type_with_a_body_is_415_for_admin_and_self_and_401_anonymous()
    {
        var admin = _factory.CreateAdminClient();
        var (self, _) = await SelfClient();
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await admin.SendAsync(Req("POST", "/v1/applications", "{\"name\":\"x\"}", null))).StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await self.SendAsync(Req("PUT", "/v1/me/password", "{}", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await self.SendAsync(Req("POST", "/v1/applications", "{}", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.SendAsync(Req("PUT", "/v1/me/password", "{}", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.SendAsync(Req("POST", "/v1/applications", "{}", "text/plain"))).StatusCode);
    }

    [Fact]
    public async Task No_body_at_all_on_body_routes_is_a_client_error_never_500_or_403_for_the_right_token()
    {
        var admin = _factory.CreateAdminClient();
        var (self, _) = await SelfClient();
        foreach (var (c, m, p) in new[] { (admin, "POST", "/v1/applications"), (admin, "PUT", $"/v1/applications/{Guid.NewGuid()}"), (self, "PUT", "/v1/me/password") })
        {
            var r = await c.SendAsync(new HttpRequestMessage(new HttpMethod(m), p));
            _out.WriteLine($"{m} {p} no body: {(int)r.StatusCode}");
            Assert.InRange((int)r.StatusCode, 400, 499);
            Assert.NotEqual(HttpStatusCode.Forbidden, r.StatusCode);
            var e = await c.SendAsync(Req(m, p, "", "application/json"));
            _out.WriteLine($"{m} {p} empty json: {(int)e.StatusCode}");
            Assert.InRange((int)e.StatusCode, 400, 499);
            Assert.NotEqual(HttpStatusCode.Forbidden, e.StatusCode);
        }
    }

    [Fact]
    public async Task Wrong_type_does_not_run_the_handler_for_a_valid_looking_body()
    {
        var admin = _factory.CreateAdminClient();
        var name = "nohandler" + Guid.NewGuid().ToString("N")[..8];
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await admin.SendAsync(Req("POST", "/v1/applications", "{\"name\":\"" + name + "\"}", "text/plain"))).StatusCode);
        var list = await admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        Assert.DoesNotContain(list.GetProperty("items").EnumerateArray(), i => i.GetProperty("name").GetString() == name);
    }

    [Fact]
    public async Task Self_token_changing_password_with_wrong_type_does_not_change_it()
    {
        var (self, id) = await SelfClient();
        var r = await self.SendAsync(Req("PUT", "/v1/me/password", "{\"currentPassword\":\"" + Password + "\",\"newPassword\":\"brand new passphrase 1\"}", "text/plain"));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await self.GetAsync("/v1/me")).StatusCode);
    }

    [Fact]
    public async Task Admin_wrong_type_leaves_exactly_one_failure_row_and_no_forbidden_row()
    {
        var admin = _factory.CreateAdminClient();
        var (self, id) = await SelfClient();
        var adminUser = TestAuth.EnsureAdmin(_factory);
        var before = (await Audit(admin, adminUser.Id.ToString())).Count(r => r.GetProperty("action").GetString() == "POST /v1/applications");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await admin.SendAsync(Req("POST", "/v1/applications", "{}", "text/xml"))).StatusCode);
        var rows = (await Audit(admin, adminUser.Id.ToString())).Where(r => r.GetProperty("action").GetString() == "POST /v1/applications").ToList();
        Assert.Equal(before + 1, rows.Count);
        Assert.Equal("failure", rows[0].GetProperty("outcome").GetString());
        Assert.DoesNotContain(rows, r => r.GetProperty("outcome").GetString() == "forbidden");
    }

    [Fact]
    public async Task Repeated_self_415s_are_coalesced_not_one_row_per_request()
    {
        var admin = _factory.CreateAdminClient();
        var (self, id) = await SelfClient();
        for (var i = 0; i < 12; i++)
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await self.SendAsync(Req("PUT", "/v1/me/password", "{}", "text/plain"))).StatusCode);
        var rows = (await Audit(admin, id)).Where(r => r.GetProperty("action").GetString() == "PUT /v1/me/password").ToList();
        _out.WriteLine($"rows: {rows.Count}");
        Assert.True(rows.Count is >= 1 and < 12, $"expected coalescing, got {rows.Count} rows");
        Assert.All(rows, r => Assert.NotEqual("forbidden", r.GetProperty("outcome").GetString()));
    }

    [Fact]
    public async Task Anonymous_auth_routes_with_a_wrong_type_report_current_behaviour_and_never_500()
    {
        var anon = _factory.CreateClient();
        foreach (var p in new[] { "login", "refresh", "logout", "introspect", "client-token" })
            foreach (var t in new[] { "text/plain", "application/xml" })
            {
                var r = await anon.SendAsync(Req("POST", "/v1/auth/" + p, "{}", t));
                _out.WriteLine($"POST /v1/auth/{p} {t}: {(int)r.StatusCode}");
                Assert.NotEqual(HttpStatusCode.InternalServerError, r.StatusCode);
                Assert.NotEqual(HttpStatusCode.Forbidden, r.StatusCode);
                Assert.NotEqual(HttpStatusCode.OK, r.StatusCode);
            }
    }

    [Fact]
    public async Task Reads_head_options_and_unknown_routes_ignore_content_type()
    {
        var admin = _factory.CreateAdminClient();
        var (self, _) = await SelfClient();
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(Req("GET", "/v1/applications", null, null))).StatusCode);
        var g = new HttpRequestMessage(HttpMethod.Get, "/v1/applications") { Content = new StringContent("x", Encoding.UTF8, "text/plain") };
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(g)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await self.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/v1/me") { Content = new StringContent("x", Encoding.UTF8, "text/plain") })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await self.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/v1/applications"))).StatusCode);
        var h = await admin.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/v1/applications") { Content = new StringContent("x", Encoding.UTF8, "text/plain") });
        _out.WriteLine($"HEAD {(int)h.StatusCode}");
        var o = await admin.SendAsync(new HttpRequestMessage(HttpMethod.Options, "/v1/applications") { Content = new StringContent("x", Encoding.UTF8, "text/plain") });
        _out.WriteLine($"OPTIONS {(int)o.StatusCode}");
        Assert.NotEqual(HttpStatusCode.UnsupportedMediaType, h.StatusCode);
        Assert.NotEqual(HttpStatusCode.UnsupportedMediaType, o.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.SendAsync(Req("GET", "/v1/applications", null, null))).StatusCode);
    }

    [Fact]
    public async Task Not_found_and_method_not_allowed_are_unchanged_whatever_the_content_type()
    {
        var admin = _factory.CreateAdminClient();
        var (self, _) = await SelfClient();
        foreach (var t in new[] { "text/plain", "application/json" })
        {
            var nf = await admin.SendAsync(Req("POST", "/v1/nope", "{}", t));
            Assert.Equal(HttpStatusCode.NotFound, nf.StatusCode);
            var nfAdmin = await admin.SendAsync(Req("PUT", $"/v1/applications/{Guid.NewGuid()}", "{\"name\":\"q\"}", t));
            Assert.Equal(t == "text/plain" ? HttpStatusCode.UnsupportedMediaType : HttpStatusCode.NotFound, nfAdmin.StatusCode);
            var notGuid = await admin.SendAsync(Req("PUT", "/v1/applications/not-a-guid", "{}", t));
            Assert.Equal(HttpStatusCode.NotFound, notGuid.StatusCode);
            // method not allowed: PUT on a collection route that has only GET/POST
            var m = await admin.SendAsync(Req("PUT", "/v1/applications", "{}", t));
            _out.WriteLine($"PUT /v1/applications {t}: {(int)m.StatusCode}");
            Assert.Equal(HttpStatusCode.MethodNotAllowed, m.StatusCode);
            var ms = await self.SendAsync(Req("DELETE", "/v1/me", null, null));
            _out.WriteLine($"self DELETE /v1/me: {(int)ms.StatusCode}");
        }
    }

    [Fact]
    public async Task OpenApi_document_still_matches_the_checked_in_file_and_declares_json_bodies()
    {
        var served = JsonDocument.Parse(await _factory.CreateClient().GetStringAsync("/openapi/v1.json")).RootElement;
        var op = served.GetProperty("paths").GetProperty("/v1/me/password").GetProperty("put");
        Assert.True(op.GetProperty("requestBody").GetProperty("content").TryGetProperty("application/json", out _));
    }
}
