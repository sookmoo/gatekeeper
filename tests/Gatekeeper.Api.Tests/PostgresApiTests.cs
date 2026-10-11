using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Infrastructure.Postgres;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Api.Tests;

/// <summary>End-to-end flow against Postgres. Skipped unless GATEKEEPER_TEST_PG is set (scripts/test-pg.sh).</summary>
public class PostgresApiTests : IDisposable
{
    private readonly string? _admin = Environment.GetEnvironmentVariable("GATEKEEPER_TEST_PG");
    private readonly string _database = $"gk_test_{Guid.NewGuid():N}";
    private WebApplicationFactory<Program>? _factory;

    private HttpClient CreateClient()
    {
        Skip.If(string.IsNullOrWhiteSpace(_admin), "GATEKEEPER_TEST_PG is not set; Postgres API tests skipped.");
        Exec($"CREATE DATABASE {_database}");
        var connection = new NpgsqlConnectionStringBuilder(_admin!) { Database = _database }.ConnectionString;
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Store:Provider", "Postgres");
            b.UseSetting("ConnectionStrings:Gatekeeper", connection);
        });
        PostgresStoreExtensions.MigrateAsync(_factory.Services).GetAwaiter().GetResult();
        return _factory.CreateClient();
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
        var user = await (await http.PostAsJsonAsync("/v1/users", new { username = "alice", email = "alice@example.com" })).Content.ReadFromJsonAsync<JsonElement>();
        var userId = user.GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.Conflict, (await http.PostAsJsonAsync("/v1/applications", new { name = "billing" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await http.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.PutAsync($"/v1/users/{userId}/roles/{Guid.NewGuid()}", null)).StatusCode);
        var roles = await http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}/roles?application={appId}");
        Assert.Equal(1, roles.GetArrayLength());
        var byName = await http.GetFromJsonAsync<JsonElement>("/v1/users?username=ALICE");
        Assert.Equal(1, byName.GetArrayLength());

        Assert.Equal(HttpStatusCode.NoContent, (await http.DeleteAsync($"/v1/applications/{appId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"/v1/roles/{roleId}")).StatusCode);
        Assert.Equal(0, (await http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}/roles")).GetArrayLength());
    }

    public void Dispose()
    {
        _factory?.Dispose();
        if (_admin is null) return;
        NpgsqlConnection.ClearAllPools();
        Exec($"DROP DATABASE IF EXISTS {_database} WITH (FORCE)");
    }

    private void Exec(string sql)
    {
        using var conn = new NpgsqlConnection(_admin);
        conn.Open();
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }
}
