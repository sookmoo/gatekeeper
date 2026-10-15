using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>The user kind migration keeps existing users as persons and refuses unknown kinds.</summary>
public class UserKindMigrationTests
{
    private const string Before = "20261012200731_AddSessions";

    private static async Task Exec(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<object?> Scalar(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return await cmd.ExecuteScalarAsync();
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    [SkippableFact]
    public async Task Existing_users_become_persons_without_expiry_and_unknown_kinds_are_refused()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        await Exec(conn, $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at) VALUES ('{Guid.NewGuid()}', 'old', 'old@example.com', '', true, now(), now())");
        await MigrateTo(conn, null);
        Assert.Equal("person", await Scalar(conn, "SELECT kind FROM users WHERE username = 'old'"));
        Assert.Equal(DBNull.Value, await Scalar(conn, "SELECT expires_at FROM users WHERE username = 'old'"));
        var bad = await Assert.ThrowsAsync<PostgresException>(() =>
            Exec(conn, $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at, kind) VALUES ('{Guid.NewGuid()}', 'x', 'x@example.com', '', true, now(), now(), 'robot')"));
        Assert.Equal("23514", bad.SqlState);
        // a test user must expire, and nobody else may
        foreach (var (kind, expires) in new[] { ("test", "NULL"), ("person", "now() + interval '1 day'"), ("shared", "now() + interval '1 day'") })
        {
            var wrong = await Assert.ThrowsAsync<PostgresException>(() =>
                Exec(conn, $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at, kind, expires_at) VALUES ('{Guid.NewGuid()}', 'y', 'y@example.com', '', true, now(), now(), '{kind}', {expires})"));
            Assert.Equal("23514", wrong.SqlState);
        }
        await MigrateTo(conn, Before); // and it rolls back
        await MigrateTo(conn, null);
    }
}
