using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>QA slice 4b: the migrations apply on top of the 4a schema (with data), roll back and forward again, and keep the privilege story.</summary>
public class Qa4bMigrationTests
{
    private const string Slice4aLast = "20261012052658_AddUserCredentials";

    private static async Task<long> Scalar(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    private static async Task Exec(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    [SkippableFact]
    public async Task Upgrading_a_4a_database_with_data_keeps_the_data_and_adds_the_new_tables()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Slice4aLast);
        Assert.Equal(0, await Scalar(conn, "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('clients','audit_events')"));
        var app = Guid.NewGuid(); var role = Guid.NewGuid(); var user = Guid.NewGuid();
        await Exec(conn, $"INSERT INTO apps (id, name) VALUES ('{app}', 'legacy'); " +
            $"INSERT INTO roles (id, app_id, name, description) VALUES ('{role}', '{app}', 'r', ''); " +
            $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at) VALUES ('{user}', 'old', 'old@example.com', '', true, now(), now()); " +
            $"INSERT INTO user_roles (user_id, role_id) VALUES ('{user}', '{role}');");
        await MigrateTo(conn, null);
        Assert.Equal(1, await Scalar(conn, "SELECT count(*) FROM apps WHERE name = 'legacy'"));
        Assert.Equal(1, await Scalar(conn, "SELECT count(*) FROM user_roles"));
        db.GrantAppAccess();

        // new tables work through the real repositories as the app role, on the upgraded data
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        var clients = sp.GetRequiredService<Gatekeeper.Application.IClientRepository>();
        var c = await clients.AddAsync(new Gatekeeper.Domain.Client(Guid.NewGuid(), "svc", app, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "h");
        await clients.AssignRoleAsync(c.Id, role);
        await sp.GetRequiredService<Gatekeeper.Application.IAppRepository>().DeleteAsync(app);
        Assert.Equal(0, await Scalar(conn, "SELECT (SELECT count(*) FROM clients) + (SELECT count(*) FROM client_roles) + (SELECT count(*) FROM client_secrets)"));
        // re-running is a no-op
        await MigrateTo(conn, null);
    }

    [SkippableFact]
    public async Task Down_then_up_again_works_and_leaves_no_stray_function()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, null);
        await MigrateTo(conn, Slice4aLast);
        Assert.Equal(0, await Scalar(conn, "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('clients','client_roles','client_secrets','audit_events')"));
        Assert.Equal(0, await Scalar(conn, "SELECT count(*) FROM pg_proc WHERE proname = 'audit_events_immutable'"));
        await MigrateTo(conn, null);
        Assert.Equal(1, await Scalar(conn, "SELECT count(*) FROM pg_proc WHERE proname = 'audit_events_immutable'"));
    }

    [SkippableFact]
    public async Task With_the_production_role_layout_the_app_role_can_append_but_not_change_the_audit_trail()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var admin = Environment.GetEnvironmentVariable("GATEKEEPER_TEST_PG")!;
        // db-roles.sql layout: gatekeeper_app exists BEFORE the migration; default privileges grant it DML on new tables.
        await Exec(admin, "SELECT pg_advisory_xact_lock(7302); DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gatekeeper_app') THEN CREATE ROLE gatekeeper_app NOLOGIN; END IF; END $$;");
        var conn = db!.MigratorConnection;
        await Exec(conn, "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gatekeeper_app");
        await MigrateTo(conn, null);
        Assert.Equal(1, await Scalar(conn, "SELECT has_table_privilege('gatekeeper_app','audit_events','INSERT')::int"));
        Assert.Equal(1, await Scalar(conn, "SELECT has_table_privilege('gatekeeper_app','audit_events','SELECT')::int"));
        Assert.Equal(0, await Scalar(conn, "SELECT has_table_privilege('gatekeeper_app','audit_events','UPDATE')::int"));
        Assert.Equal(0, await Scalar(conn, "SELECT has_table_privilege('gatekeeper_app','audit_events','DELETE')::int"));
        Assert.Equal(0, await Scalar(conn, "SELECT has_table_privilege('gatekeeper_app','audit_events','TRUNCATE')::int"));
        foreach (var t in new[] { "clients", "client_roles", "client_secrets" })
            Assert.Equal(1, await Scalar(conn, $"SELECT (has_table_privilege('gatekeeper_app','{t}','INSERT') AND has_table_privilege('gatekeeper_app','{t}','DELETE') AND has_table_privilege('gatekeeper_app','{t}','SELECT'))::int"));
        // the app role has no way to drop the trigger
        Assert.Equal(0, await Scalar(conn, "SELECT has_schema_privilege('gatekeeper_app','public','CREATE')::int"));
        await Exec(conn, "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM gatekeeper_app");
    }
}
