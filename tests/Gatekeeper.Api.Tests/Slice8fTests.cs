using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 8f: a wrong Content-Type is a binding failure (415) after authorisation, never the 403 of a policy that did not belong to the route.</summary>
public class Slice8fTests : IDisposable
{
    private const string Password = "correct horse battery";
    private static readonly string[] WrongTypes = ["text/plain", "application/xml", "application/x-www-form-urlencoded"];

    private readonly WebApplicationFactory<Program> _factory = new();

    public void Dispose() => _factory.Dispose();

    /// <summary>Every state-changing /v1 route that takes a body (the ones that declare what they accept), as (method, concrete path, route is under /v1/me).</summary>
    private List<(string Method, string Path, bool Self)> BodyRoutes() =>
        _factory.Services.GetServices<EndpointDataSource>().SelectMany(d => d.Endpoints).OfType<RouteEndpoint>()
            .Where(e => e.RoutePattern.RawText!.StartsWith("/v1/", StringComparison.Ordinal) && !e.RoutePattern.RawText.StartsWith("/v1/auth/", StringComparison.Ordinal)
                        && e.Metadata.GetMetadata<IAcceptsMetadata>() is not null)
            .SelectMany(e => (e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? []).Where(m => m is "POST" or "PUT" or "PATCH" or "DELETE")
                .Select(m => (Method: m, Path: Concrete(e.RoutePattern), Self: e.RoutePattern.RawText!.StartsWith("/v1/me/", StringComparison.Ordinal))))
            .ToList();

    private static string Concrete(Microsoft.AspNetCore.Routing.Patterns.RoutePattern pattern) =>
        string.Concat(pattern.PathSegments.Select(s => "/" + string.Concat(s.Parts.Select(p => p switch
        {
            Microsoft.AspNetCore.Routing.Patterns.RoutePatternLiteralPart l => l.Content,
            Microsoft.AspNetCore.Routing.Patterns.RoutePatternParameterPart => Guid.NewGuid().ToString(),
            _ => "",
        }))));

    private async Task<(HttpClient Client, string Id)> SelfClient()
    {
        var admin = _factory.CreateAdminClient();
        var name = $"usr-{Guid.NewGuid():N}"[..20];
        var r = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
        var id = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        var login = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return (c, id.ToString());
    }

    private static Task<HttpResponseMessage> Send(HttpClient c, string method, string path, string contentType) =>
        c.SendAsync(new HttpRequestMessage(new HttpMethod(method), path) { Content = new StringContent("{}", Encoding.UTF8, contentType) });

    private async Task<List<JsonElement>> Audit(HttpClient admin, string actor) =>
        (await admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=200")).GetProperty("items").EnumerateArray().ToList();

    [Fact]
    public void The_route_table_has_body_routes_on_both_sides()
    {
        var routes = BodyRoutes();
        Assert.Contains(routes, r => r.Self && r.Method == "PUT" && r.Path.EndsWith("/password"));
        Assert.True(routes.Count(r => !r.Self) >= 10, "the management routes with a body must be in the table");
    }

    [Fact]
    public async Task An_admin_token_with_a_wrong_content_type_gets_415_on_every_body_route()
    {
        var admin = _factory.CreateAdminClient();
        foreach (var (method, path, self) in BodyRoutes().Where(r => !r.Self))
            foreach (var type in WrongTypes)
            {
                var r = await Send(admin, method, path, type);
                Assert.True(r.StatusCode == HttpStatusCode.UnsupportedMediaType, $"{method} {path} as {type}: {(int)r.StatusCode}");
            }
        // An admin is a person too: the self-service routes accept the same token.
        foreach (var (method, path, _) in BodyRoutes().Where(r => r.Self))
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await Send(admin, method, path, "text/plain")).StatusCode);
    }

    [Fact]
    public async Task A_self_token_gets_415_on_the_self_routes_and_403_on_the_admin_routes()
    {
        var (self, _) = await SelfClient();
        foreach (var (method, path, isSelf) in BodyRoutes())
            foreach (var type in WrongTypes)
            {
                var r = await Send(self, method, path, type);
                var expected = isSelf ? HttpStatusCode.UnsupportedMediaType : HttpStatusCode.Forbidden;
                Assert.True(r.StatusCode == expected, $"{method} {path} as {type}: {(int)r.StatusCode}, expected {(int)expected}");
            }
    }

    [Fact]
    public async Task Without_a_token_a_wrong_content_type_is_still_401()
    {
        var anon = _factory.CreateClient();
        foreach (var (method, path, _) in BodyRoutes())
            Assert.Equal(HttpStatusCode.Unauthorized, (await Send(anon, method, path, "text/plain")).StatusCode);
    }

    [Fact]
    public async Task The_self_password_route_audits_the_415_like_any_binding_failure_and_writes_no_forbidden_row()
    {
        var admin = _factory.CreateAdminClient();
        var (self, id) = await SelfClient();
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await Send(self, "PUT", "/v1/me/password", "text/plain")).StatusCode);

        var rows = (await Audit(admin, id)).Where(r => r.GetProperty("action").GetString() == "PUT /v1/me/password").ToList();
        var row = Assert.Single(rows);
        Assert.Equal("failure", row.GetProperty("outcome").GetString());
        Assert.Equal("BadHttpRequestException", row.GetProperty("detail").GetString());
        Assert.DoesNotContain(await Audit(admin, id), r => r.GetProperty("outcome").GetString() == "forbidden" && r.GetProperty("action").GetString() == "PUT /v1/me/password");
    }

    [Fact]
    public async Task A_self_token_on_an_admin_route_still_leaves_one_forbidden_row()
    {
        var admin = _factory.CreateAdminClient();
        var (self, id) = await SelfClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(self, "POST", "/v1/applications", "text/plain")).StatusCode);
        var row = Assert.Single(await Audit(admin, id), r => r.GetProperty("action").GetString() == "POST /v1/applications");
        Assert.Equal("forbidden", row.GetProperty("outcome").GetString());
    }

    [Fact]
    public async Task Anonymous_auth_routes_answer_415_for_a_wrong_type_with_no_audit_row_and_no_throttle_failure_but_introspect_stays_401()
    {
        var admin = _factory.CreateAdminClient();
        var anon = _factory.CreateClient();
        var address = System.Net.IPAddress.None.ToString(); // what the test server reports as the caller
        var before = (await Audit(admin, "")).Count(r => r.GetProperty("action").GetString()!.Contains("/v1/auth/"));
        foreach (var route in new[] { "login", "refresh", "logout", "client-token" })
            for (var i = 0; i < 12; i++)
                Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await Send(anon, "POST", "/v1/auth/" + route, "text/plain")).StatusCode);

        var after = (await Audit(admin, "")).Count(r => r.GetProperty("action").GetString()!.Contains("/v1/auth/"));
        Assert.Equal(before, after);
        var s = _factory.Services;
        Assert.Equal(0, s.GetRequiredService<Gatekeeper.Api.LoginThrottle>().AddressFailures(address));
        foreach (var key in new[] { "client", "refresh" })
            Assert.Equal(0, s.GetRequiredKeyedService<Gatekeeper.Api.LoginThrottle>(key).AddressFailures(address));
        // introspect authenticates the caller before reading the body, so it keeps its own 401 (and does count a failure).
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(anon, "POST", "/v1/auth/introspect", "text/plain")).StatusCode);
    }

    [Fact]
    public async Task In_Production_a_wrong_type_is_415_with_a_fixed_problem_body_and_one_coalescible_failure_row()
    {
        using var prod = _factory.WithWebHostBuilder(b => b.UseEnvironment("Production"));
        var admin = prod.CreateAdminClient();
        var r = await Send(admin, "POST", "/v1/applications", "text/x-attacker-script");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, r.StatusCode);
        var body = await r.Content.ReadAsStringAsync();
        var problem = JsonDocument.Parse(body).RootElement;
        Assert.Equal(415, problem.GetProperty("status").GetInt32());
        Assert.DoesNotContain("attacker", body);
        Assert.DoesNotContain("script", body);

        // A self token: the failure is a coalescible row (the same kind as every other binding failure), not a forbidden one.
        var name = $"usr-{Guid.NewGuid():N}"[..20];
        var created = await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" });
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password });
        var login = await prod.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = "gatekeeper", refresh = true });
        var self = prod.CreateClient();
        self.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await Send(self, "PUT", "/v1/me/password", "text/plain")).StatusCode);
        var rows = (await Audit(admin, id.ToString())).Where(x => x.GetProperty("action").GetString() == "PUT /v1/me/password").ToList();
        Assert.Equal("failure", Assert.Single(rows).GetProperty("outcome").GetString());
    }

    [Fact]
    public void The_framework_content_type_matcher_policy_is_gone()
    {
        Assert.DoesNotContain(_factory.Services.GetServices<MatcherPolicy>(), p => p.GetType().Name == "AcceptsMatcherPolicy");
    }

    [Fact]
    public void No_route_pattern_and_method_pair_is_registered_twice()
    {
        var pairs = _factory.Services.GetServices<EndpointDataSource>().SelectMany(d => d.Endpoints).OfType<RouteEndpoint>()
            .SelectMany(e => (e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? ["*"]).Select(m => (Route: e.RoutePattern.RawText, Method: m)))
            .GroupBy(p => p).Where(g => g.Count() > 1).Select(g => $"{g.Key.Method} {g.Key.Route}").ToList();
        Assert.True(pairs.Count == 0, "duplicate endpoints: " + string.Join(", ", pairs));
    }
}
