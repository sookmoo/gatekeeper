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

/// <summary>Slice 7c: the BEFORE UPDATE triggers that enforce the version bump (Postgres only; the in-memory store computes it itself).</summary>
public class Slice7cTriggerTests
{
    private const string Before = "20261025160920_AddSessionCutoff";
    private static readonly DateTimeOffset T0 = new(2126, 10, 25, 12, 0, 0, TimeSpan.Zero);

    private static async Task Exec(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<long> Version(string conn, string table, Guid id)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand($"SELECT version FROM {table} WHERE id = '{id}'", c);
        return (long)(await cmd.ExecuteScalarAsync())!;
    }

    private static async Task<List<string>> Rows(string conn, string sql)
    {
        await using var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await using var r = await cmd.ExecuteReaderAsync();
        var list = new List<string>();
        while (await r.ReadAsync()) list.Add(r.IsDBNull(0) ? "<null>" : r.GetValue(0).ToString()!);
        return list;
    }

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    private sealed record Ids(Guid App, Guid Role, Guid User, Guid Client);

    private static async Task<Ids> Populate(string conn)
    {
        Guid app = Guid.NewGuid(), role = Guid.NewGuid(), user = Guid.NewGuid(), client = Guid.NewGuid();
        await Exec(conn,
            $"INSERT INTO apps (id, name) VALUES ('{app}', 'shop'); " +
            $"INSERT INTO roles (id, app_id, name, description) VALUES ('{role}', '{app}', 'reader', 'r'); " +
            $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at) VALUES ('{user}', 'old', 'old@example.com', 'Old', true, now(), now()); " +
            $"INSERT INTO clients (id, name, app_id, is_active, created_at, updated_at) VALUES ('{client}', 'checkout', '{app}', true, now(), now())");
        return new(app, role, user, client);
    }


    [SkippableFact]
    public async Task A_raw_update_of_an_own_column_bumps_once_and_other_columns_do_not()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, null);
        var i = await Populate(conn);

        (string Table, Guid Id, string Set)[] own =
        [
            ("apps", i.App, "name = 'shop2'"),
            ("roles", i.Role, "name = 'writer'"), ("roles", i.Role, "description = 'w'"),
            ("users", i.User, "username = 'new'"), ("users", i.User, "email = 'n@example.com'"), ("users", i.User, "display_name = 'N'"),
            ("users", i.User, "is_active = false"), ("users", i.User, "expires_at = now() + interval '1 day', kind = 'test'"),
            ("clients", i.Client, "name = 'pay'"), ("clients", i.Client, "is_active = false"),
        ];
        foreach (var (table, id, set) in own)
        {
            var was = await Version(conn, table, id);
            await Exec(conn, $"UPDATE {table} SET {set} WHERE id = '{id}'");
            Assert.True(was + 1 == await Version(conn, table, id), $"{table}: {set}");
        }
        // a case-only rename of a citext column counts
        var v = await Version(conn, "apps", i.App);
        await Exec(conn, $"UPDATE apps SET name = 'SHOP2' WHERE id = '{i.App}'");
        Assert.Equal(v + 1, await Version(conn, "apps", i.App));
        // a statement that changes several own columns bumps once; one that changes nothing does not
        v = await Version(conn, "users", i.User);
        await Exec(conn, $"UPDATE users SET username = 'multi', email = 'm@example.com', display_name = 'M', is_active = true WHERE id = '{i.User}'");
        Assert.Equal(v + 1, await Version(conn, "users", i.User));
        await Exec(conn, $"UPDATE users SET username = 'multi', display_name = 'M' WHERE id = '{i.User}'");
        Assert.Equal(v + 1, await Version(conn, "users", i.User));
        // a writer that sets the version itself still gets exactly old + 1 (never the value it wrote, never +2)
        await Exec(conn, $"UPDATE users SET version = 99 WHERE id = '{i.User}'");
        Assert.Equal(v + 2, await Version(conn, "users", i.User));
        await Exec(conn, $"UPDATE users SET version = version + 1, display_name = 'Z' WHERE id = '{i.User}'");
        Assert.Equal(v + 3, await Version(conn, "users", i.User));
    }

    [SkippableFact]
    public async Task The_cut_off_and_updated_at_alone_do_not_bump_and_a_cut_off_in_a_real_change_bumps_once()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, null);
        var i = await Populate(conn);
        Assert.Equal(1, await Version(conn, "users", i.User));

        await Exec(conn, $"UPDATE users SET sessions_valid_after = now() WHERE id = '{i.User}'");
        Assert.Equal(1, await Version(conn, "users", i.User));
        await Exec(conn, $"UPDATE users SET updated_at = now() + interval '1 hour' WHERE id = '{i.User}'");
        Assert.Equal(1, await Version(conn, "users", i.User));
        await Exec(conn, $"UPDATE users SET updated_at = now(), sessions_valid_after = now() WHERE id = '{i.User}'");
        Assert.Equal(1, await Version(conn, "users", i.User));
        await Exec(conn, $"UPDATE clients SET updated_at = now() + interval '1 hour' WHERE id = '{i.Client}'");
        Assert.Equal(1, await Version(conn, "clients", i.Client));
        // password, role link and session rows are other tables and never touch the version
        await Exec(conn, $"INSERT INTO user_roles (user_id, role_id) VALUES ('{i.User}', '{i.Role}'); INSERT INTO user_credentials (user_id, hash, updated_at) VALUES ('{i.User}', 'h', now())");
        Assert.Equal(1, await Version(conn, "users", i.User));

        await Exec(conn, $"UPDATE users SET sessions_valid_after = now(), is_active = false, updated_at = now() WHERE id = '{i.User}'");
        Assert.Equal(2, await Version(conn, "users", i.User));
    }

    [SkippableFact]
    public async Task An_update_through_the_repositories_gives_exactly_plus_one_and_the_returned_value_is_the_stored_one()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        await MigrateTo(db!.MigratorConnection, null);
        db.GrantAppAccess();
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        var apps = sp.GetRequiredService<IAppRepository>();
        var roles = sp.GetRequiredService<IRoleRepository>();
        var users = sp.GetRequiredService<IUserRepository>();
        var clients = sp.GetRequiredService<IClientRepository>();
        var conn = db.MigratorConnection;

        var app = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var role = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "reader", "r"));
        var user = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));
        var client = await clients.AddAsync(new Client(Guid.NewGuid(), "checkout", app.Id, true, T0, T0), "secret-hash");

        // conditional and unconditional, changed and identical: always +1
        var a2 = await apps.UpdateAsync(app with { Name = "shop2" }, 1);
        Assert.Equal(2, a2!.Version);
        Assert.Equal(2, await Version(conn, "apps", app.Id));
        var a3 = await apps.UpdateAsync(a2);
        Assert.Equal(3, a3!.Version);
        Assert.Equal(3, await Version(conn, "apps", app.Id));
        var r2 = await roles.UpdateAsync(role with { Description = "x" }, 1);
        Assert.Equal(2, r2!.Version);
        Assert.Equal(3, (await roles.UpdateAsync(r2, 2))!.Version);
        Assert.Equal(3, await Version(conn, "roles", role.Id));
        var u2 = await users.UpdateAsync(user with { DisplayName = "B" }, 1);
        Assert.Equal(2, u2!.Version);
        Assert.Equal(3, (await users.UpdateAsync(u2, 2))!.Version); // identical: bumps once
        Assert.Equal(3, await Version(conn, "users", user.Id));
        var u4 = await users.UpdateAsync(u2 with { IsActive = false, SessionsValidAfter = T0.AddHours(1) });
        Assert.Equal(4, u4!.Version); // the cut-off statement in the same transaction does not add a second bump
        Assert.Equal(4, await Version(conn, "users", user.Id));
        var c2 = await clients.UpdateAsync(client with { IsActive = false, UpdatedAt = T0.AddMinutes(1) }, 1);
        Assert.Equal(2, c2!.Version);
        Assert.Equal(3, (await clients.UpdateAsync(c2, 2))!.Version);
        Assert.Equal(3, await Version(conn, "clients", client.Id));

        // the 412 path is unchanged: a stale version refuses and writes nothing
        await Assert.ThrowsAsync<PreconditionFailedException>(() => apps.UpdateAsync(app with { Name = "late" }, 1));
        Assert.Equal(3, await Version(conn, "apps", app.Id));
        Assert.Equal("shop2", (await apps.GetAsync(app.Id))!.Name);

        // password, cut-off-only writes (revoke-all) and role links leave the version alone
        await sp.GetRequiredService<ICredentialRepository>().SetAsync(user.Id, "hash", T0, null);
        await sp.GetRequiredService<ISessionRepository>().RevokeAllAndCutOffAsync(user.Id, T0.AddHours(2));
        await users.AssignRoleAsync(user.Id, role.Id);
        Assert.Equal(4, await Version(conn, "users", user.Id));
        Assert.Equal(4, (await users.GetAsync(user.Id))!.Version);
    }

    [SkippableFact]
    public async Task Concurrent_writers_each_bump_once()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, null);
        var i = await Populate(conn);
        const int writers = 12;

        // raw writers on separate connections: the row lock serialises them and the trigger sees the latest committed version each time
        await Task.WhenAll(Enumerable.Range(0, writers).Select(n =>
            Exec(conn, $"UPDATE roles SET description = 'w{n}' WHERE id = '{i.Role}'")));
        Assert.Equal(1 + writers, await Version(conn, "roles", i.Role));

        // and through the store (unconditional updates queue on the row lock)
        db.GrantAppAccess();
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        var users = sp.GetRequiredService<IUserRepository>();
        var user = (await users.GetAsync(i.User))!;
        await Task.WhenAll(Enumerable.Range(0, writers).Select(n => users.UpdateAsync(user with { DisplayName = $"n{n}" })));
        Assert.Equal(1 + writers, await Version(conn, "users", i.User));

        // a raw writer and a conditional store writer racing on one version: exactly one version step per successful write
        var before = await Version(conn, "users", i.User);
        var raw = Exec(conn, $"UPDATE users SET email = 'raw@example.com' WHERE id = '{i.User}'");
        var viaStore = users.UpdateAsync((await users.GetAsync(i.User))! with { DisplayName = "cond" }, before)
            .ContinueWith(t => t.IsCompletedSuccessfully, TaskScheduler.Default);
        await raw;
        var stored = await viaStore;
        Assert.Equal(before + 1 + (stored ? 1 : 0), await Version(conn, "users", i.User));
    }

    [SkippableFact]
    public async Task The_app_role_cannot_drop_disable_or_replace_the_triggers_and_they_run_for_it()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, null);
        db.GrantAppAccess();
        var i = await Populate(conn);

        foreach (var t in new[] { "apps", "roles", "users", "clients" })
        {
            foreach (var sql in new[]
            {
                $"DROP TRIGGER {t}_bump_version ON {t}",
                $"ALTER TABLE {t} DISABLE TRIGGER {t}_bump_version",
                $"ALTER TABLE {t} DISABLE TRIGGER ALL",
                $"DROP FUNCTION {t}_bump_version()",
                $"CREATE OR REPLACE FUNCTION {t}_bump_version() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
            })
            {
                var ex = await Assert.ThrowsAsync<PostgresException>(() => Exec(db.AppConnection, sql));
                Assert.True(ex.SqlState is "42501", $"{sql}: {ex.SqlState}"); // insufficient_privilege / must be owner
            }
        }
        // the app role's own raw writes are bumped too, and it cannot set the version to anything it likes
        await Exec(db.AppConnection, $"UPDATE users SET display_name = 'App', version = 500 WHERE id = '{i.User}'");
        Assert.Equal(2, await Version(conn, "users", i.User));
        Assert.Equal(["apps_bump_version", "clients_bump_version", "roles_bump_version", "users_bump_version"],
            await Rows(conn, "SELECT tgname FROM pg_trigger WHERE tgname LIKE '%\\_bump\\_version' ORDER BY 1"));
    }

    [SkippableFact]
    public async Task Migrating_populated_data_changes_no_row_and_down_and_up_work_and_the_lock_timeout_applies()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, Before);
        var i = await Populate(conn);
        await Exec(conn, $"UPDATE roles SET version = 7 WHERE id = '{i.Role}'"); // no trigger yet: the writer's value stands

        await MigrateTo(conn, null);
        Assert.Equal(7, await Version(conn, "roles", i.Role));
        Assert.Equal(1, await Version(conn, "users", i.User));
        Assert.Equal(["4"], await Rows(conn, "SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%\\_bump\\_version'"));

        await MigrateTo(conn, Before);
        Assert.Equal(["0"], await Rows(conn, "SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%\\_bump\\_version'"));
        Assert.Equal(["0"], await Rows(conn, "SELECT count(*) FROM pg_proc WHERE proname LIKE '%\\_bump\\_version'"));
        await Exec(conn, $"UPDATE users SET display_name = 'No trigger' WHERE id = '{i.User}'");
        Assert.Equal(1, await Version(conn, "users", i.User)); // older behaviour: nothing bumps without the trigger

        // gives up cleanly under a conflicting lock (nothing half-applied), then works when retried
        await using (var holder = new NpgsqlConnection(conn))
        {
            await holder.OpenAsync();
            await using var tx = await holder.BeginTransactionAsync();
            await using (var read = new NpgsqlCommand("SELECT count(*) FROM users", holder, tx)) await read.ExecuteScalarAsync();
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => MigrateTo(conn, null));
            Assert.Contains("55P03", ex.ToString());
        }
        Assert.Equal(["0"], await Rows(conn, "SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%\\_bump\\_version'"));
        await MigrateTo(conn, null);
        await Exec(conn, $"UPDATE users SET display_name = 'Trigger' WHERE id = '{i.User}'");
        Assert.Equal(2, await Version(conn, "users", i.User));
    }

    [SkippableFact]
    public async Task An_insert_cannot_choose_a_version_and_the_app_role_cannot_drop_disable_or_call_the_functions()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        var conn = db!.MigratorConnection;
        await MigrateTo(conn, null);
        db.GrantAppAccess();
        var i = await Populate(conn);
        Guid app = Guid.NewGuid(), role = Guid.NewGuid(), user = Guid.NewGuid(), client = Guid.NewGuid();
        // as the data-only role: chosen, huge and NULL versions are all stored as 1
        foreach (var (v, n) in new[] { ("5", 1), ("9223372036854775807", 2), ("NULL", 3), ("0", 4) })
        {
            app = Guid.NewGuid(); role = Guid.NewGuid(); user = Guid.NewGuid(); client = Guid.NewGuid();
            await Exec(db.AppConnection,
                $"INSERT INTO apps (id, name, version) VALUES ('{app}', 'a{n}', {v}); " +
                $"INSERT INTO roles (id, app_id, name, description, version) VALUES ('{role}', '{app}', 'r{n}', 'd', {v}); " +
                $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at, version) VALUES ('{user}', 'u{n}', 'u{n}@example.com', 'U', true, now(), now(), {v}); " +
                $"INSERT INTO clients (id, name, app_id, is_active, created_at, updated_at, version) VALUES ('{client}', 'c{n}', '{app}', true, now(), now(), {v})");
            Assert.Equal(1, await Version(conn, "apps", app));
            Assert.Equal(1, await Version(conn, "roles", role));
            Assert.Equal(1, await Version(conn, "users", user));
            Assert.Equal(1, await Version(conn, "clients", client));
        }
        // the row stays updatable and the upsert's UPDATE branch bumps once
        await Exec(db.AppConnection, $"UPDATE apps SET name = 'changed' WHERE id = '{app}'");
        Assert.Equal(2, await Version(conn, "apps", app));
        await Exec(db.AppConnection, $"INSERT INTO apps (id, name, version) VALUES ('{app}', 'upsert', 77) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name");
        Assert.Equal(3, await Version(conn, "apps", app));
        // both triggers fire for the app role and for the owner although EXECUTE was revoked from PUBLIC
        await Exec(conn, $"UPDATE apps SET name = 'owner' WHERE id = '{i.App}'");
        Assert.Equal(2, await Version(conn, "apps", i.App));

        foreach (var t in new[] { "apps", "roles", "users", "clients" })
            foreach (var sql in new[]
            {
                $"DROP TRIGGER {t}_start_version ON {t}",
                $"ALTER TABLE {t} DISABLE TRIGGER {t}_start_version",
                $"DROP FUNCTION {t}_start_version()",
                $"CREATE OR REPLACE FUNCTION {t}_start_version() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
                $"SELECT {t}_bump_version()",
                $"SELECT {t}_start_version()",
            })
            {
                var ex = await Assert.ThrowsAsync<PostgresException>(() => Exec(db.AppConnection, sql));
                Assert.True(ex.SqlState is "42501", $"{sql}: {ex.SqlState}");
            }
        Assert.Equal(["4"], await Rows(conn, "SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%\\_start\\_version'"));
    }
}
