using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

public class AuditApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public AuditApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..24];

    private async Task<JsonElement[]> Events(string query) =>
        (await _admin.GetFromJsonAsync<JsonElement>("/v1/audit?" + query)).GetProperty("items").EnumerateArray().ToArray();

    [Fact]
    public async Task Changes_are_recorded_with_actor_route_target_and_outcome_but_reads_are_not()
    {
        var name = Unique("aud");
        var created = await (await _admin.PostAsJsonAsync("/v1/applications", new { name })).Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetString()!;
        await _admin.GetAsync($"/v1/applications/{id}");
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PostAsJsonAsync("/v1/applications", new { name })).StatusCode);
        await _admin.PatchAsJsonAsync($"/v1/applications/{id}", new { name = Unique("aud") });
        await _admin.DeleteAsync($"/v1/applications/{id}");

        var admin = TestAuth.EnsureAdmin(_factory);
        var mine = (await Events($"actor={admin.Id}&limit=200")).Where(e => e.GetProperty("target").GetString()!.Contains(id) || e.GetProperty("action").GetString() == "POST /v1/applications").ToArray();
        Assert.All(mine, e => Assert.Equal(admin.Id.ToString(), e.GetProperty("actor").GetString()));
        var actions = mine.Select(e => e.GetProperty("action").GetString()).ToList();
        Assert.Contains("PATCH /v1/applications/{id:guid}", actions);
        Assert.Contains("DELETE /v1/applications/{id:guid}", actions);
        Assert.DoesNotContain("GET /v1/applications/{id:guid}", actions);
        var failed = mine.Where(e => e.GetProperty("outcome").GetString() == "failure").ToArray();
        Assert.Contains(failed, e => e.GetProperty("detail").GetString() == "ConflictException");
    }

    [Fact]
    public async Task Passwords_never_reach_the_audit_trail()
    {
        var name = Unique("pw");
        var user = await (await _admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com" })).Content.ReadFromJsonAsync<JsonElement>();
        const string secret = "super secret passphrase 123";
        await _admin.PutAsJsonAsync($"/v1/users/{user.GetProperty("id").GetString()}/password", new { password = secret });
        var raw = await _admin.GetStringAsync("/v1/audit?limit=200");
        Assert.DoesNotContain(secret, raw);
        Assert.Contains("/password", raw);
    }

    [Fact]
    public async Task Logins_are_recorded_and_attacker_text_is_sanitised()
    {
        var anon = _factory.CreateClient();
        var evil = "ghost\nFAKE success admin" + new string('x', 500);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/v1/auth/login", new { username = evil, password = "wrong password here", application = "gatekeeper" })).StatusCode);
        var failures = await Events("actor=anonymous&action=auth.login&limit=200");
        var mine = failures.First(e => e.GetProperty("detail").GetString()!.StartsWith("username=ghost"));
        var detail = mine.GetProperty("detail").GetString()!;
        Assert.DoesNotContain('\n', detail);
        Assert.True(detail.Length <= 200);
        Assert.Equal("failure", mine.GetProperty("outcome").GetString());

        var admin = TestAuth.EnsureAdmin(_factory);
        var ok = await anon.PostAsJsonAsync("/v1/auth/login", new { username = TestAuth.AdminName, password = TestAuth.AdminPassword, application = "gatekeeper" });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains(await Events($"actor={admin.Id}&action=auth.login"), e => e.GetProperty("outcome").GetString() == "success");
    }

    [Fact]
    public async Task Audit_endpoint_needs_admin_and_pages()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/v1/audit")).StatusCode);
        for (var i = 0; i < 3; i++) await _admin.PostAsJsonAsync("/v1/applications", new { name = Unique("pg") });
        var page = await _admin.GetFromJsonAsync<JsonElement>("/v1/audit?limit=2");
        Assert.Equal(2, page.GetProperty("items").GetArrayLength());
        Assert.NotNull(page.GetProperty("nextCursor").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/audit?limit=0")).StatusCode);
    }

    [Fact]
    public async Task A_failing_audit_store_does_not_break_the_change()
    {
        using var f = _factory.WithWebHostBuilder(b => b.ConfigureServices(s =>
            s.AddSingleton<IAuditRepository, ThrowingAudit>()));
        var c = f.CreateAdminClient();
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsJsonAsync("/v1/applications", new { name = Unique("up") })).StatusCode);
    }

    private sealed class ThrowingAudit : IAuditRepository
    {
        public Task AppendAsync(Gatekeeper.Domain.AuditEvent entry, CancellationToken ct = default) => throw new StoreUnavailableException("down", null);
        public Task<IReadOnlyList<Gatekeeper.Domain.AuditEvent>> ListAsync(string? actor = null, string? action = null, Slice? slice = null, CancellationToken ct = default) => throw new StoreUnavailableException("down", null);
    }
}
