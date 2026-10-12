using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Infrastructure.Postgres;
using Microsoft.Extensions.DependencyInjection;
using Gatekeeper.Tests;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>
/// QA differential tests: the same operations run against the in-memory store and Postgres and must
/// give the same observable result. Skipped unless GATEKEEPER_TEST_PG is set.
/// </summary>
public class PostgresParityTests : IDisposable
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _databases = [];

    private (IAppRepository Apps, IRoleRepository Roles, IUserRepository Users) Mem()
    {
        var p = new ServiceCollection().AddInMemoryStore().BuildServiceProvider();
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IRoleRepository>(), p.GetRequiredService<IUserRepository>());
    }

    private (IAppRepository Apps, IRoleRepository Roles, IUserRepository Users) Pg()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set.");
        _databases.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IRoleRepository>(), p.GetRequiredService<IUserRepository>());
    }

    [SkippableFact]
    public async Task Audit_trigger_blocks_changes_even_for_the_owner()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set.");
        _databases.Add(db!);
        _providers.Add(PgStores.OpenAsAppRole(db!));
        await using var conn = new Npgsql.NpgsqlConnection(db!.MigratorConnection);
        await conn.OpenAsync();
        await using (var insert = new Npgsql.NpgsqlCommand(
            "INSERT INTO audit_events (id, at, actor, action, outcome) VALUES (gen_random_uuid(), now(), 'a', 'b', 'success')", conn))
            await insert.ExecuteNonQueryAsync();
        foreach (var sql in new[] { "UPDATE audit_events SET actor = 'x'", "DELETE FROM audit_events", "TRUNCATE audit_events" })
        {
            await using var cmd = new Npgsql.NpgsqlCommand(sql, conn);
            var ex = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Contains("append-only", ex.MessageText);
        }
    }

    public void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _databases) d.Dispose();
    }

    private static User U(string name, string? email = null, string display = "x", DateTimeOffset? at = null) =>
        new(Guid.NewGuid(), name, email ?? $"{name}@example.com", display, true, at ?? DateTimeOffset.UtcNow, at ?? DateTimeOffset.UtcNow);

    private static async Task<string> Outcome(Func<Task> f)
    {
        try { await f(); return "ok"; }
        catch (Exception e) { return $"{e.GetType().Name}: {e.Message}"; }
    }

    [SkippableFact]
    public async Task Ordering_matches_for_punctuation_digits_and_case()
    {
        var names = new[] { "a", "a-b", "a_b", "a.b", "ab", "a1", "a-1", "b", "1a", "z", "a--b", "a-c", "a_c", "a.c" };
        var results = new List<string[]>();
        foreach (var (apps, roles, users) in new[] { Mem(), Pg() })
        {
            var app = await apps.AddAsync(new App(Guid.NewGuid(), "parent"));
            foreach (var n in names)
            {
                await apps.AddAsync(new App(Guid.NewGuid(), "x" + n));
                await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, n, ""));
                await users.AddAsync(U(n));
            }
            results.Add([.. (await apps.ListAsync()).Select(a => a.Name),
                         .. (await roles.ListByAppAsync(app.Id)).Select(r => r.Name),
                         .. (await users.ListAsync()).Select(u => u.Username)]);
        }
        Assert.Equal(results[0], results[1]);
    }

    [SkippableFact]
    public async Task Assign_with_both_user_and_role_missing_gives_same_message_modulo_ids()
    {
        var outs = new List<string>();
        foreach (var (_, _, users) in new[] { Mem(), Pg() })
        {
            var o = await Outcome(() => users.AssignRoleAsync(Guid.Empty, Guid.Parse("11111111-1111-1111-1111-111111111111")));
            outs.Add(o);
        }
        Assert.Equal(outs[0], outs[1]);
    }

    [SkippableFact]
    public async Task User_timestamps_roundtrip_exactly()
    {
        var (_, _, users) = Pg();
        var u = U("alice", at: new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero).AddTicks(1234560));
        var added = await users.AddAsync(u);
        var got = await users.GetAsync(u.Id);
        Assert.Equal(added, got); // microsecond-aligned values (Clock.UtcNowMicros) round-trip exactly
    }

    [SkippableFact]
    public async Task Update_with_both_username_and_email_conflicting_reports_same_error()
    {
        var outs = new List<string>();
        foreach (var (_, _, users) in new[] { Mem(), Pg() })
        {
            await users.AddAsync(U("a", "a@x.se"));
            await users.AddAsync(U("b", "b@x.se"));
            var c = await users.AddAsync(U("c", "c@x.se"));
            outs.Add(await Outcome(() => users.UpdateAsync(c with { Username = "A", Email = "B@x.se" })));
            outs.Add(await Outcome(() => users.AddAsync(U("A", "B@x.se"))));
        }
        Assert.Equal(outs[..2], outs[2..]);
    }

    [SkippableTheory]
    [InlineData("a@x.se", "A@X.SE")]
    [InlineData("Mixed.Case@Example.COM", "mixed.case@example.com")]
    [InlineData("a+tag@x.se", "A+TAG@x.se")]
    public async Task Email_uniqueness_for_ascii_matches(string e1, string e2)
    {
        var outs = new List<string>();
        foreach (var (_, _, users) in new[] { Mem(), Pg() })
        {
            await users.AddAsync(U("u1", e1));
            outs.Add(await Outcome(() => users.AddAsync(U("u2", e2))));
        }
        Assert.Equal(outs[0], outs[1]);
    }

    [SkippableTheory]
    [InlineData("emoji 😀🎉 日本語 ñ")]
    [InlineData("")]
    [InlineData("  padded  ")]
    public async Task Display_name_roundtrips_or_fails_identically(string display)
    {
        var outs = new List<string>();
        var got = new List<string?>();
        foreach (var (_, _, users) in new[] { Mem(), Pg() })
        {
            var u = U("alice", display: display);
            outs.Add(await Outcome(() => users.AddAsync(u)));
            got.Add((await users.GetAsync(u.Id))?.DisplayName);
        }
        Assert.Equal(outs[0], outs[1]);
        Assert.Equal(got[0], got[1]);
    }

    [SkippableFact]
    public async Task Very_long_strings_roundtrip()
    {
        var (_, roles, users) = Pg();
        var (apps, _, _) = Pg();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), new string('a', 5000)));
        var role = await roles.AddAsync(new Role(Guid.NewGuid(), Guid.NewGuid(), "x", ""))
            .ContinueWith(t => t.Exception!.InnerException);
        Assert.IsType<NotFoundException>(role);
        var u = await users.AddAsync(U("alice", display: new string('é', 1_000_000)));
        Assert.Equal(1_000_000, (await users.GetAsync(u.Id))!.DisplayName.Length);
        Assert.Equal(5000, app.Name.Length);
    }

    [SkippableFact]
    public async Task Update_and_delete_on_missing_rows_match()
    {
        var outs = new List<string>();
        foreach (var (apps, roles, users) in new[] { Mem(), Pg() })
        {
            var a = await apps.AddAsync(new App(Guid.NewGuid(), "a"));
            var r = await roles.AddAsync(new Role(Guid.NewGuid(), a.Id, "r", ""));
            var u = await users.AddAsync(U("u"));
            await apps.DeleteAsync(a.Id);
            await users.DeleteAsync(u.Id);
            outs.Add(string.Join("|",
                await Outcome(async () => Assert.Null(await apps.UpdateAsync(a with { Name = "zz" }))),
                await Outcome(async () => Assert.Null(await roles.UpdateAsync(r with { Name = "zz" }))),
                await Outcome(async () => Assert.Null(await users.UpdateAsync(u with { Username = "zz" }))),
                await Outcome(async () => Assert.Empty(await roles.ListByAppAsync(a.Id))),
                await Outcome(async () => Assert.Empty(await users.ListRolesAsync(u.Id))),
                await Outcome(async () => Assert.False(await users.RevokeRoleAsync(u.Id, r.Id))),
                await Outcome(async () => Assert.False(await roles.DeleteAsync(r.Id)))));
        }
        Assert.Equal(outs[0], outs[1]);
        Assert.DoesNotContain("Exception", outs[1]);
    }

    [SkippableFact]
    public async Task Update_of_missing_row_with_conflicting_name_returns_null_like_inmemory()
    {
        var outs = new List<string>();
        foreach (var (apps, _, users) in new[] { Mem(), Pg() })
        {
            await apps.AddAsync(new App(Guid.NewGuid(), "taken"));
            await users.AddAsync(U("taken"));
            outs.Add(await Outcome(async () => Assert.Null(await apps.UpdateAsync(new App(Guid.NewGuid(), "taken")))));
            outs.Add(await Outcome(async () => Assert.Null(await users.UpdateAsync(U("taken")))));
        }
        Assert.Equal(outs[..2], outs[2..]);
    }

    [SkippableFact]
    public async Task Concurrent_adds_of_same_name_yield_exactly_one_winner_and_only_conflicts()
    {
        var (apps, _, users) = Pg();
        var res = await Task.WhenAll(Enumerable.Range(0, 20).Select(i =>
            Outcome(() => apps.AddAsync(new App(Guid.NewGuid(), i % 2 == 0 ? "same" : "SAME")))));
        Assert.Equal(1, res.Count(r => r == "ok"));
        Assert.All(res.Where(r => r != "ok"), r => Assert.StartsWith("ConflictException", r));
        var res2 = await Task.WhenAll(Enumerable.Range(0, 20).Select(i =>
            Outcome(() => users.AddAsync(U("same", $"e{i}@x.se")))));
        Assert.Equal(1, res2.Count(r => r == "ok"));
        Assert.All(res2.Where(r => r != "ok"), r => Assert.StartsWith("ConflictException", r));
    }

    [SkippableFact]
    public async Task Concurrent_role_add_assign_and_parent_delete_never_leak_non_domain_errors()
    {
        var (apps, roles, users) = Pg();
        for (var round = 0; round < 15; round++)
        {
            var app = await apps.AddAsync(new App(Guid.NewGuid(), $"app{round}"));
            var role = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "r", ""));
            var user = await users.AddAsync(U($"u{round}"));
            var tasks = new List<Task<string>>
            {
                Outcome(() => apps.DeleteAsync(app.Id)),
                Outcome(() => roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "r2", ""))),
                Outcome(() => users.AssignRoleAsync(user.Id, role.Id)),
                Outcome(() => users.AssignRoleAsync(user.Id, role.Id)),
                Outcome(() => roles.UpdateAsync(role with { Name = "r3" })),
                Outcome(() => users.DeleteAsync(user.Id)),
                Outcome(() => users.UpdateAsync(user with { DisplayName = "n" })),
            };
            foreach (var r in await Task.WhenAll(tasks))
                Assert.True(r == "ok" || r.StartsWith("NotFoundException") || r.StartsWith("ConflictException"), r);
            // after app delete, nothing may remain
            Assert.Empty(await roles.ListByAppAsync(app.Id));
            Assert.Empty(await users.ListRolesAsync(user.Id));
        }
    }

    [SkippableFact]
    public async Task Migrate_is_idempotent_and_preserves_data()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set.");
        _databases.Add(db!);
        var migrator = new ServiceCollection().AddPostgresStore(db!.MigratorConnection).BuildServiceProvider();
        _providers.Add(migrator);
        await PostgresStoreExtensions.MigrateAsync(migrator);
        await migrator.GetRequiredService<IAppRepository>().AddAsync(new App(Guid.NewGuid(), "keep"));
        await Task.WhenAll(PostgresStoreExtensions.MigrateAsync(migrator), PostgresStoreExtensions.MigrateAsync(migrator)); // concurrent runs
        await PostgresStoreExtensions.MigrateAsync(migrator);
        Assert.Single(await migrator.GetRequiredService<IAppRepository>().ListAsync());
    }

    [SkippableFact]
    public async Task App_role_has_data_access_only_and_cannot_change_the_schema()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set.");
        _databases.Add(db!);
        _providers.Add(PgStores.OpenAsAppRole(db!));

        await using var conn = new Npgsql.NpgsqlConnection(db!.AppConnection);
        await conn.OpenAsync();
        foreach (var ddl in new[] { "CREATE TABLE evil (id int)", "DROP TABLE users", "ALTER TABLE users ADD COLUMN x int", "CREATE EXTENSION IF NOT EXISTS hstore" })
        {
            await using var cmd = new Npgsql.NpgsqlCommand(ddl, conn);
            var ex = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Equal("42501", ex.SqlState); // insufficient_privilege
        }
        await using var select = new Npgsql.NpgsqlCommand("SELECT count(*) FROM users", conn);
        Assert.Equal(0L, await select.ExecuteScalarAsync());
    }

    [SkippableFact]
    public async Task Username_filter_is_exact_not_pattern_and_case_insensitive()
    {
        var outs = new List<string>();
        foreach (var (_, _, users) in new[] { Mem(), Pg() })
        {
            await users.AddAsync(U("alice")); await users.AddAsync(U("alice2")); await users.AddAsync(U("al_ce"));
            foreach (var f in new[] { "ALICE", "al%", "al_ce", "AL_CE", "", " alice" })
                outs.Add(f.Length + ":" + await Outcome(async () => { var l = await users.ListAsync(null, f); Assert.True(l.Count < 3); }) + string.Join(",", (await Try(() => users.ListAsync(null, f))).Select(u => u.Username)));
        }
        Assert.Equal(outs[..6], outs[6..]);
    }

    private static async Task<IReadOnlyList<User>> Try(Func<Task<IReadOnlyList<User>>> f)
    { try { return await f(); } catch { return []; } }
}
