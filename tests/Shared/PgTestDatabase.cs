using Npgsql;

namespace Gatekeeper.Tests;

/// <summary>
/// A throwaway database for one test. Created and migrated with the admin connection
/// (GATEKEEPER_TEST_PG), then served through a data-only role so the tests prove the runtime
/// never needs DDL rights.
/// </summary>
internal sealed class PgTestDatabase : IDisposable
{
    private const string AppRole = "gk_test_app";
    private const string AppPassword = "gk-test-app";

    private readonly string _admin;
    private readonly string _name = $"gk_test_{Guid.NewGuid():N}";

    private PgTestDatabase(string admin) => _admin = admin;

    /// <summary>Null when GATEKEEPER_TEST_PG is not set.</summary>
    public static PgTestDatabase? TryCreate()
    {
        var admin = Environment.GetEnvironmentVariable("GATEKEEPER_TEST_PG");
        if (string.IsNullOrWhiteSpace(admin)) return null;
        var db = new PgTestDatabase(admin);
        EnsureAppRole(admin);
        Exec(admin, $"CREATE DATABASE {db._name}");
        return db;
    }

    /// <summary>Connection used to migrate (database owner = admin).</summary>
    public string MigratorConnection => new NpgsqlConnectionStringBuilder(_admin) { Database = _name }.ConnectionString;

    /// <summary>Connection for the service under test: data access only.</summary>
    public string AppConnection => new NpgsqlConnectionStringBuilder(_admin)
        { Database = _name, Username = AppRole, Password = AppPassword }.ConnectionString;

    /// <summary>Call after migrating: grants the app role data access to the migrated tables.</summary>
    public void GrantAppAccess() => Exec(MigratorConnection,
        $"GRANT USAGE ON SCHEMA public TO {AppRole}; " +
        $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {AppRole}; " +
        $"REVOKE ALL ON DATABASE {_name} FROM PUBLIC; GRANT CONNECT ON DATABASE {_name} TO {AppRole}");

    public void Dispose()
    {
        NpgsqlConnection.ClearAllPools();
        Exec(_admin, $"DROP DATABASE IF EXISTS {_name} WITH (FORCE)");
    }

    // Roles are cluster-wide and tests run in parallel, so serialise creation with an advisory lock.
    private static void EnsureAppRole(string admin) => Exec(admin,
        "SELECT pg_advisory_lock(7301); " +
        $"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AppRole}') THEN " +
        $"CREATE ROLE {AppRole} LOGIN PASSWORD '{AppPassword}' NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$; " +
        "SELECT pg_advisory_unlock(7301);");

    private static void Exec(string connectionString, string sql)
    {
        using var conn = new NpgsqlConnection(connectionString);
        conn.Open();
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }
}
