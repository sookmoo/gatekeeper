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

/// <summary>Independent QA of slice 7c (version triggers), written from the spec: column inventory, every own column incl. citext case and NULL transitions, inserts/deletes, ExecuteUpdate, app-role limits, migration re-run.</summary>
public class Slice7cQaTests
{
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
        while (await r.ReadAsync()) list.Add(r.IsDBNull(0) ? "<null>" : r.GetValue(0).ToString()!);
        return list;
    }

    private static async Task<long> V(string conn, string table, Guid id) => long.Parse((await Rows(conn, $"SELECT version FROM {table} WHERE id = '{id}'")).Single());

    private static async Task MigrateTo(string conn, string? target)
    {
        using var sp = new ServiceCollection().AddPostgresStore(conn).BuildServiceProvider();
        await using var db = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();
        await db.GetService<IMigrator>().MigrateAsync(target);
    }

    private sealed record Ids(Guid App, Guid App2, Guid Role, Guid User, Guid Client);

    private static async Task<Ids> Populate(string conn)
    {
        Guid app = Guid.NewGuid(), app2 = Guid.NewGuid(), role = Guid.NewGuid(), user = Guid.NewGuid(), client = Guid.NewGuid();
        await Exec(conn,
            $"INSERT INTO apps (id, name) VALUES ('{app}', 'shop'), ('{app2}', 'other'); " +
            $"INSERT INTO roles (id, app_id, name, description) VALUES ('{role}', '{app}', 'reader', 'r'); " +
            $"INSERT INTO users (id, username, email, display_name, is_active, created_at, updated_at) VALUES ('{user}', 'old', 'old@example.com', 'Old', true, now(), now()); " +
            $"INSERT INTO clients (id, name, app_id, is_active, created_at, updated_at) VALUES ('{client}', 'checkout', '{app}', true, now(), now())");
        return new(app, app2, role, user, client);
    }

    private static PgTestDatabase Db()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        return db!;
    }

    [SkippableFact]
    public async Task Column_inventory_every_column_is_either_covered_by_the_trigger_or_deliberately_excluded()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        var excluded = new[] { "id", "version", "updated_at", "sessions_valid_after" };
        var expected = new Dictionary<string, string[]>
        {
            ["apps"] = ["name"],
            ["roles"] = ["app_id", "description", "name"],
            ["users"] = ["created_at", "display_name", "email", "expires_at", "is_active", "kind", "username"],
            ["clients"] = ["app_id", "created_at", "is_active", "name"],
        };
        foreach (var (table, own) in expected)
        {
            var cols = await Rows(conn, $"SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '{table}' ORDER BY 1");
            Assert.Equal(own.Concat(excluded.Where(c => cols.Contains(c))).Order().ToList(), cols); // a new column must be decided on here AND in the function
            var def = (await Rows(conn, $"SELECT pg_get_functiondef('{table}_bump_version'::regproc)")).Single();
            foreach (var c in own) Assert.True(def.Contains($"new.{c} ", StringComparison.OrdinalIgnoreCase) || def.Contains($"new.{c}\n", StringComparison.OrdinalIgnoreCase) || def.Contains($"NEW.{c}", StringComparison.Ordinal), $"{table}.{c} missing from function");
            foreach (var c in new[] { "updated_at", "sessions_valid_after" }) Assert.DoesNotContain($"NEW.{c}", def);
            Assert.Contains("OLD.version + 1", def);
            Assert.DoesNotContain("NEW.version + 1", def);
            Assert.Contains("search_path", def); // hardened
            var ins = (await Rows(conn, $"SELECT pg_get_functiondef('{table}_start_version'::regproc)")).Single();
            Assert.Contains("NEW.version := 1", ins);
            Assert.Contains("search_path", ins);
            foreach (var c in own) Assert.DoesNotContain($"NEW.{c}", ins); // the insert function touches nothing but the version
        }
    }

    [SkippableFact]
    public async Task Every_own_column_bumps_exactly_once_including_citext_case_only_changes_and_null_transitions_and_unchanged_values_do_not()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        var i = await Populate(conn);
        (string T, Guid Id, string Set)[] changes =
        [
            ("apps", i.App, "name = 'SHOP'"),                            // case only
            ("roles", i.Role, "name = 'READER'"),                        // case only (citext)
            ("roles", i.Role, "description = ''"),                       // empty string vs value
            ("roles", i.Role, $"app_id = '{i.App2}'"),
            ("users", i.User, "username = 'OLD'"),                       // case only
            ("users", i.User, "email = 'OLD@EXAMPLE.COM'"),             // case only
            ("users", i.User, "display_name = ''"),
            ("users", i.User, "created_at = created_at + interval '1 microsecond'"),
            ("users", i.User, "kind = 'shared'"),
            ("users", i.User, "kind = 'test', expires_at = now() + interval '1 day'"),   // NULL -> value
            ("users", i.User, "expires_at = now() + interval '2 days'"),                  // value -> value
            ("users", i.User, "kind = 'person', expires_at = NULL"),                      // value -> NULL
            ("clients", i.Client, "name = 'CHECKOUT'"),
            ("clients", i.Client, $"app_id = '{i.App2}'"),
            ("clients", i.Client, "created_at = created_at - interval '1 microsecond'"),
        ];
        foreach (var (t, id, set) in changes)
        {
            var was = await V(conn, t, id);
            await Exec(conn, $"UPDATE {t} SET {set} WHERE id = '{id}'");
            Assert.True(was + 1 == await V(conn, t, id), $"{t}: {set}");
        }
        // writing the value a column already has is not a change (NULL = NULL included)
        (string T, Guid Id, string Cols)[] same =
        [
            ("apps", i.App, "name = name"), ("roles", i.Role, "name = name, description = description, app_id = app_id"),
            ("users", i.User, "username = username, email = email, display_name = display_name, is_active = is_active, created_at = created_at, kind = kind, expires_at = expires_at"),
            ("clients", i.Client, "name = name, app_id = app_id, is_active = is_active, created_at = created_at"),
        ];
        foreach (var (t, id, cols) in same)
        {
            var was = await V(conn, t, id);
            await Exec(conn, $"UPDATE {t} SET {cols} WHERE id = '{id}'");
            await Exec(conn, $"UPDATE {t} SET version = version WHERE id = '{id}'");
            Assert.True(was == await V(conn, t, id), $"{t}: {cols}");
        }
        // updated_at and cut-off excluded, also together with an unchanged own value
        var u = await V(conn, "users", i.User);
        await Exec(conn, $"UPDATE users SET updated_at = now(), sessions_valid_after = now(), display_name = display_name WHERE id = '{i.User}'");
        await Exec(conn, $"UPDATE users SET sessions_valid_after = NULL WHERE id = '{i.User}'");
        Assert.Equal(u, await V(conn, "users", i.User));
        // NULL written to version is replaced, not stored
        await Exec(conn, $"UPDATE users SET version = NULL WHERE id = '{i.User}'");
        Assert.Equal(u + 1, await V(conn, "users", i.User));
        // a multi-row statement bumps each row once
        await Exec(conn, $"INSERT INTO roles (id, app_id, name, description) VALUES (gen_random_uuid(), '{i.App}', 'a', 'x'), (gen_random_uuid(), '{i.App}', 'b', 'x')");
        await Exec(conn, $"UPDATE roles SET description = 'y' WHERE app_id = '{i.App}'");
        Assert.Equal(["2", "2"], await Rows(conn, $"SELECT version FROM roles WHERE app_id = '{i.App}'"));
    }

    [SkippableFact]
    public async Task Insert_and_delete_are_not_affected_and_a_rename_of_the_app_does_not_touch_its_roles_or_clients()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        var i = await Populate(conn);
        var id = Guid.NewGuid();
        await Exec(conn, $"INSERT INTO apps (id, name, version) VALUES ('{id}', 'ins', 5)");
        Assert.Equal(1, await V(conn, "apps", id)); // since the review round a new row always starts at 1
        // an upsert that takes the UPDATE branch IS an update and bumps
        await Exec(conn, $"INSERT INTO apps (id, name, version) VALUES ('{id}', 'ins2', 1) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name");
        Assert.Equal(2, await V(conn, "apps", id));
        await Exec(conn, $"UPDATE apps SET name = 'renamed' WHERE id = '{i.App}'");
        Assert.Equal(1, await V(conn, "roles", i.Role));
        Assert.Equal(1, await V(conn, "clients", i.Client));
        await Exec(conn, $"DELETE FROM apps WHERE id = '{i.App}'"); // cascades, no trigger involvement
        Assert.Equal(["0"], await Rows(conn, $"SELECT count(*) FROM roles WHERE id = '{i.Role}'"));
        Assert.Equal(["0"], await Rows(conn, $"SELECT count(*) FROM clients WHERE id = '{i.Client}'"));
    }

    [SkippableFact]
    public async Task EF_ExecuteUpdate_and_raw_sql_paths_bump_once_even_when_they_also_add_one_themselves()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        db.GrantAppAccess();
        var i = await Populate(conn);
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        await using var ctx = await sp.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync();

        await ctx.Users.Where(u => u.Id == i.User).ExecuteUpdateAsync(s => s.SetProperty(u => u.DisplayName, "EU"));
        Assert.Equal(2, await V(conn, "users", i.User));
        await ctx.Users.Where(u => u.Id == i.User).ExecuteUpdateAsync(s => s.SetProperty(u => u.DisplayName, "EU2").SetProperty(u => u.Version, u => u.Version + 1));
        Assert.Equal(3, await V(conn, "users", i.User)); // not +3 / +2: old + 1
        await ctx.Users.Where(u => u.Id == i.User).ExecuteUpdateAsync(s => s.SetProperty(u => u.SessionsValidAfter, DateTimeOffset.UtcNow));
        Assert.Equal(3, await V(conn, "users", i.User));
        await ctx.Database.ExecuteSqlInterpolatedAsync($"UPDATE clients SET is_active = false, version = version + 5 WHERE id = {i.Client}");
        Assert.Equal(2, await V(conn, "clients", i.Client));
    }

    [SkippableFact]
    public async Task Conditional_store_writers_on_one_version_exactly_one_wins_and_the_version_moves_once()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        db.GrantAppAccess();
        using var sp = new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
        var clients = sp.GetRequiredService<IClientRepository>();
        var apps = sp.GetRequiredService<IAppRepository>();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "x"));
        var t0 = new DateTimeOffset(2126, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var c = await clients.AddAsync(new Client(Guid.NewGuid(), "c", app.Id, true, t0, t0), "h");
        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(async n =>
        {
            try { await clients.UpdateAsync(c with { Name = $"c{n}" }, 1); return true; }
            catch (PreconditionFailedException) { return false; }
        }));
        Assert.Single(results, r => r);
        Assert.Equal(2, await V(conn, "clients", c.Id));
    }

    [SkippableFact]
    public async Task The_app_role_cannot_bypass_the_triggers_by_other_means()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        db.GrantAppAccess();
        await Populate(conn);
        foreach (var sql in new[]
        {
            "SET session_replication_role = replica",
            "ALTER TABLE users ENABLE ALWAYS TRIGGER users_bump_version",
            "ALTER FUNCTION users_bump_version() SET search_path = public",
            "ALTER FUNCTION users_bump_version() RENAME TO x",
            "ALTER FUNCTION users_bump_version() OWNER TO gk_test_app",
            "CREATE TRIGGER evil BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION users_bump_version()",
            "ALTER TABLE users DROP COLUMN version",
            "ALTER TABLE users RENAME TO users2",
        })
        {
            var ex = await Assert.ThrowsAsync<PostgresException>(() => Exec(db.AppConnection, sql));
            Assert.True(ex.SqlState is "42501", $"{sql}: {ex.SqlState} {ex.MessageText}");
        }
        // functions are not SECURITY DEFINER (run as the writer) and carry a fixed search_path
        Assert.Equal(["false|{\"search_path=pg_catalog, pg_temp\"}"],
            await Rows(conn, "SELECT string_agg(DISTINCT (prosecdef)::text || '|' || proconfig::text, ';') FROM pg_proc WHERE proname LIKE '%\\_bump\\_version' HAVING count(*) = 4"));
    }

    [SkippableFact]
    public async Task Running_the_migration_again_is_a_no_op_and_down_up_on_populated_data_keeps_every_version()
    {
        using var db = Db();
        var conn = db.MigratorConnection;
        await MigrateTo(conn, null);
        var i = await Populate(conn);
        await Exec(conn, $"UPDATE users SET display_name = 'a' WHERE id = '{i.User}'");
        await MigrateTo(conn, null); // second run
        Assert.Equal(["4"], await Rows(conn, "SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%\\_bump\\_version'"));
        Assert.Equal(2, await V(conn, "users", i.User));
        await MigrateTo(conn, "20261025160920_AddSessionCutoff");
        Assert.Equal(2, await V(conn, "users", i.User));
        await MigrateTo(conn, null);
        Assert.Equal(2, await V(conn, "users", i.User));
        await Exec(conn, $"UPDATE users SET display_name = 'b' WHERE id = '{i.User}'");
        Assert.Equal(3, await V(conn, "users", i.User));
    }
}
