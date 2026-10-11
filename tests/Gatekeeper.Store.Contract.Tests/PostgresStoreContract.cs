using Gatekeeper.Application;
using Gatekeeper.Infrastructure.Postgres;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>
/// Runs the contract against a real Postgres. Set GATEKEEPER_TEST_PG to an admin connection string
/// (see scripts/test-pg.sh); otherwise the tests are reported as skipped.
/// Each test gets its own freshly migrated database.
/// </summary>
public class PostgresStoreContract : StoreContract
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<string> _databases = [];
    private string? _admin;

    protected override (IAppRepository, IRoleRepository, IUserRepository) CreateStore()
    {
        _admin = Environment.GetEnvironmentVariable("GATEKEEPER_TEST_PG");
        Skip.If(string.IsNullOrWhiteSpace(_admin), "GATEKEEPER_TEST_PG is not set; Postgres contract tests skipped.");

        var database = $"gk_test_{Guid.NewGuid():N}";
        Exec(_admin!, $"CREATE DATABASE {database}");
        _databases.Add(database);

        var connection = new NpgsqlConnectionStringBuilder(_admin!) { Database = database }.ConnectionString;
        var provider = new ServiceCollection().AddPostgresStore(connection).BuildServiceProvider();
        _providers.Add(provider);
        PostgresStoreExtensions.MigrateAsync(provider).GetAwaiter().GetResult();

        return (provider.GetRequiredService<IAppRepository>(),
                provider.GetRequiredService<IRoleRepository>(),
                provider.GetRequiredService<IUserRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        NpgsqlConnection.ClearAllPools();
        foreach (var db in _databases) Exec(_admin!, $"DROP DATABASE IF EXISTS {db} WITH (FORCE)");
        base.Dispose();
    }

    private static void Exec(string connectionString, string sql)
    {
        using var conn = new NpgsqlConnection(connectionString);
        conn.Open();
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }
}
