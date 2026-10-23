using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 6d: AddVersions is safe on a database that already holds rows, works for the data-only role, and rolls back and forward.</summary>
public class Slice6dMigrationTests
{
    private const string Before = "20261022160105_AddAuditIndexes";
    private static readonly string[] Tables = ["apps", "roles", "users", "clients"];

    private static async Task Exec(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<List<string>> Rows(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await using var r = await cmd.ExecuteReaderAsync();
        var list = new List<string>();
        while (await r.ReadAsync()) list.Add(r.GetValue(0).ToString()!);
        return list;
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    [SkippableFact]
    public async Task Existing_rows_get_version_one_the_column_is_required_and_the_app_role_can_use_it()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        Guid app = Guid.NewGuid(), role = Guid.NewGuid(), user = Guid.NewGuid(), client = Guid.NewGuid();
        await Exec(conn,
            $"INSERT INTO apps (id, name) VALUES ('{app}', 'shop'); " +
            $"INSERT INTO roles (id, app_id, name, description) VALUES ('{role}', '{app}', 'reader', 'r'); " +
            $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at) VALUES ('{user}', 'old', 'old@example.com', 'Old', true, now(), now()); " +
            $"INSERT INTO clients (id, name, app_id, is_active, created_at, updated_at) VALUES ('{client}', 'checkout', '{app}', true, now(), now()); " +
            $"INSERT INTO user_roles (user_id, role_id) VALUES ('{user}', '{role}')");

        await MigrateTo(conn, null);

        foreach (var table in Tables)
        {
            Assert.Equal(["1"], await Rows(conn, $"SELECT version::text FROM {table}"));
            Assert.Equal(["bigint|NO|1"], await Rows(conn,
                $"SELECT data_type || '|' || is_nullable || '|' || column_default FROM information_schema.columns WHERE table_name = '{table}' AND column_name = 'version'"));
        }
        // rows written by older code (no version column in the INSERT) get 1, and NULL is refused
        await Exec(conn, "INSERT INTO apps (id, name) VALUES (gen_random_uuid(), 'legacy')");
        Assert.Equal(["1"], await Rows(conn, "SELECT version::text FROM apps WHERE name = 'legacy'"));
        var nullVersion = await Assert.ThrowsAsync<PostgresException>(() => Exec(conn, "UPDATE apps SET version = NULL"));
        Assert.Equal("23502", nullVersion.SqlState);

        // the data-only role reads and conditionally writes the new column through the stores
        db.GrantAppAccess();
        using (var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider())
        {
            var users = sp.GetRequiredService<IUserRepository>();
            var old = (await users.GetAsync(user))!;
            Assert.Equal(1, old.Version);
            Assert.Equal(2, (await users.UpdateAsync(old with { DisplayName = "New" }, 1))!.Version);
            await Assert.ThrowsAsync<PreconditionFailedException>(() => users.UpdateAsync(old with { DisplayName = "Again" }, 1));
            Assert.Equal(2, (await sp.GetRequiredService<IAppRepository>().UpdateAsync(new App(app, "shop2"), 1))!.Version);
            Assert.Equal(2, (await sp.GetRequiredService<IClientRepository>().UpdateAsync((await sp.GetRequiredService<IClientRepository>().GetAsync(client))! with { Name = "c2" }, 1))!.Version);
            Assert.Equal(2, (await sp.GetRequiredService<IRoleRepository>().UpdateAsync((await sp.GetRequiredService<IRoleRepository>().GetAsync(role))! with { Name = "r2" }, 1))!.Version);
        }

        // down removes the columns and keeps the data; up again starts every row at 1
        await MigrateTo(conn, Before);
        foreach (var table in Tables)
            Assert.Empty(await Rows(conn, $"SELECT 1 FROM information_schema.columns WHERE table_name = '{table}' AND column_name = 'version'"));
        Assert.Equal(["New"], await Rows(conn, "SELECT display_name FROM users"));
        Assert.Equal(["shop2", "legacy"], (await Rows(conn, "SELECT name FROM apps")).OrderByDescending(x => x).ToList());
        await MigrateTo(conn, null);
        Assert.Equal(["1"], await Rows(conn, "SELECT DISTINCT version::text FROM users"));
    }
}
