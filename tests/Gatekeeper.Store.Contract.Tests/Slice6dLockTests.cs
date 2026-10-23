using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 6d review: unconditional updates wait for a row lock for at most 2 s (then Busy), and the lock does not block inserts that reference the row.</summary>
public class Slice6dLockTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    private static async Task<NpgsqlConnection> HoldRowLock(string conn, Guid userId, string mode)
    {
        var c = new NpgsqlConnection(conn);
        await c.OpenAsync();
        await new NpgsqlCommand("BEGIN", c).ExecuteNonQueryAsync();
        await new NpgsqlCommand($"SELECT 1 FROM users WHERE id = '{userId}' {mode}", c).ExecuteNonQueryAsync();
        return c;
    }

    [SkippableFact]
    public async Task An_unconditional_update_gives_up_with_busy_when_the_row_lock_is_held_and_works_after_release()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        using var sp = PgStores.OpenAsAppRole(db!);
        var users = sp.GetRequiredService<IUserRepository>();
        var u = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));

        await using (var holder = await HoldRowLock(db!.MigratorConnection, u.Id, "FOR UPDATE"))
        {
            await Assert.ThrowsAsync<BusyException>(() => users.UpdateAsync(u with { DisplayName = "B" }));
            Assert.Equal(1, (await users.GetAsync(u.Id))!.Version); // nothing changed, plain reads are not blocked
            await new NpgsqlCommand("ROLLBACK", holder).ExecuteNonQueryAsync();
        }
        Assert.Equal(2, (await users.UpdateAsync(u with { DisplayName = "B" }))!.Version);
    }

    [SkippableFact]
    public async Task The_lock_mode_does_not_block_rows_that_reference_the_user()
    {
        using var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set");
        using var sp = PgStores.OpenAsAppRole(db!);
        var users = sp.GetRequiredService<IUserRepository>();
        var app = await sp.GetRequiredService<IAppRepository>().AddAsync(new App(Guid.NewGuid(), "shop"));
        var u = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "A", true, T0, T0));

        // the lock the unconditional update takes: a session (foreign key to the user) can still be inserted meanwhile
        await using var holder = await HoldRowLock(db!.MigratorConnection, u.Id, "FOR NO KEY UPDATE");
        var add = sp.GetRequiredService<ISessionRepository>().AddAsync(new Session(Guid.NewGuid(), u.Id, app.Id, T0, T0, T0.AddDays(1), null), "h");
        Assert.Same(add, await Task.WhenAny(add, Task.Delay(TimeSpan.FromSeconds(10))));
        await add;
        await new NpgsqlCommand("ROLLBACK", holder).ExecuteNonQueryAsync();
    }
}
