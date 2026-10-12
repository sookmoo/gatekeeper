using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Infrastructure.Postgres;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Gatekeeper.Tests;

namespace Gatekeeper.Api.Tests;

/// <summary>End-to-end flow against Postgres. Skipped unless GATEKEEPER_TEST_PG is set (scripts/test-pg.sh).</summary>
public class PostgresApiTests : IDisposable
{
    private PgTestDatabase? _db;
    private WebApplicationFactory<Program>? _factory;

    private HttpClient CreateClient(string? connection = null)
    {
        _db = PgTestDatabase.TryCreate();
        Skip.If(_db is null, "GATEKEEPER_TEST_PG is not set; Postgres API tests skipped.");

        using (var migrator = new ServiceCollection().AddPostgresStore(_db!.MigratorConnection).BuildServiceProvider())
            PostgresStoreExtensions.MigrateAsync(migrator).GetAwaiter().GetResult();
        _db.GrantAppAccess();

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Store:Provider", "Postgres");
            b.UseSetting("Auth:SigningKeyPem", TestKey.Pem);
            b.UseSetting("ConnectionStrings:Gatekeeper", connection ?? _db.AppConnection);
        });
        if (connection is null) return _factory.CreateAdminClient();
        // The database is deliberately unreachable, so no administrator can be created in it: use a synthetic token.
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", TestAuth.Token(_factory, "gatekeeper", ["admin"]));
        return c;
    }

    [SkippableFact]
    public async Task Full_flow_and_readiness_against_postgres()
    {
        var http = CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/ready")).StatusCode);

        var app = await (await http.PostAsJsonAsync("/v1/applications", new { name = "billing" })).Content.ReadFromJsonAsync<JsonElement>();
        var appId = app.GetProperty("id").GetGuid();
        var role = await (await http.PostAsJsonAsync($"/v1/applications/{appId}/roles", new { name = "admin" })).Content.ReadFromJsonAsync<JsonElement>();
        var roleId = role.GetProperty("id").GetGuid();
        var created = await (await http.PostAsJsonAsync("/v1/users", new { username = "alice", email = "alice@example.com" })).Content.ReadFromJsonAsync<JsonElement>();
        var userId = created.GetProperty("id").GetGuid();

        // The POST response must equal what a later GET returns (timestamps are microsecond-aligned).
        var fetched = await http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}");
        Assert.Equal(created.GetProperty("createdAt").GetString(), fetched.GetProperty("createdAt").GetString());
        Assert.Equal(created.GetProperty("updatedAt").GetString(), fetched.GetProperty("updatedAt").GetString());

        Assert.Equal(HttpStatusCode.Conflict, (await http.PostAsJsonAsync("/v1/applications", new { name = "billing" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await http.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.PutAsync($"/v1/users/{userId}/roles/{Guid.NewGuid()}", null)).StatusCode);
        var roles = (await http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}/roles?application={appId}")).GetProperty("items");
        Assert.Equal(1, roles.GetArrayLength());
        var byName = (await http.GetFromJsonAsync<JsonElement>("/v1/users?username=ALICE")).GetProperty("items");
        Assert.Equal(1, byName.GetArrayLength());
        Assert.Equal(0, ((await http.GetFromJsonAsync<JsonElement>("/v1/users?username=a%00")).GetProperty("items")).GetArrayLength());

        Assert.Equal(HttpStatusCode.NoContent, (await http.DeleteAsync($"/v1/applications/{appId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"/v1/roles/{roleId}")).StatusCode);
        Assert.Equal(0, ((await http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}/roles")).GetProperty("items")).GetArrayLength());
    }

    [SkippableTheory]
    [InlineData("a\\u0000b")]
    [InlineData("a\\u001b[31mb")]
    [InlineData("a\\ud800b")]
    [InlineData("a\\u202eb")]
    public async Task Unsafe_text_is_rejected_with_400_not_500(string displayJson)
    {
        var http = CreateClient();
        var body = new StringContent($$"""{"username":"bob","email":"bob@example.com","displayName":"{{displayJson}}"}""",
            System.Text.Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync("/v1/users", body)).StatusCode);
    }

    [SkippableFact]
    public async Task Unreachable_database_gives_503_and_not_ready()
    {
        // Port 1 refuses connections.
        var http = CreateClient("Host=127.0.0.1;Port=1;Database=x;Username=x;Password=x;Timeout=2;Command Timeout=2");
        var response = await http.GetAsync("/v1/users");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health")).StatusCode);
    }

    [SkippableFact]
    public async Task Unmigrated_database_is_not_ready()
    {
        _db = PgTestDatabase.TryCreate();
        Skip.If(_db is null, "GATEKEEPER_TEST_PG is not set; Postgres API tests skipped.");
        _db!.GrantAppAccess(); // empty database: no tables, no migrations applied
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Store:Provider", "Postgres");
            b.UseSetting("Auth:SigningKeyPem", TestKey.Pem);
            b.UseSetting("ConnectionStrings:Gatekeeper", _db.AppConnection);
        });
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", TestAuth.Token(_factory, "gatekeeper", ["admin"]));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await c.GetAsync("/health/ready")).StatusCode);
    }

    public void Dispose()
    {
        _factory?.Dispose();
        _db?.Dispose();
    }
}
