using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>QA for slice 8g, run against every store.</summary>
public abstract class Qa8gStoreTests : IDisposable
{
    protected abstract IUserRepository Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static User U(string name, string? email = null, bool active = true, DateTimeOffset? expires = null) =>
        new(Guid.NewGuid(), name, email ?? $"{name}@example.com", name, active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            expires is null ? UserKind.Person : UserKind.Test, expires);

    private static string[] Names(IReadOnlyList<User> l) => [.. l.Select(u => u.Username)];

    [SkippableFact]
    public async Task Unicode_case_folding_and_quote_characters_are_literal()
    {
        var users = Open();
        foreach (var n in new[] { "ünï-1", "ÜNÏ-2", "o'brien", "a\"b", "100%", "a--b", "a[b]" }) await users.AddAsync(U(n));
        Assert.Equal(["ünï-1", "ÜNÏ-2"], Names(await users.ListAsync(usernamePrefix: "ÜN")).Order(StringComparer.Ordinal).Reverse().Reverse().OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
        Assert.Equal(["o'brien"], Names(await users.ListAsync(usernamePrefix: "o'")));
        Assert.Equal(["100%"], Names(await users.ListAsync(usernamePrefix: "100%")));
        Assert.Empty(await users.ListAsync(usernamePrefix: "10%"));
        Assert.Equal(["a[b]"], Names(await users.ListAsync(usernamePrefix: "a[")));   // not a character class
        Assert.Equal(["a--b"], Names(await users.ListAsync(usernamePrefix: "a--")));
    }

    [SkippableFact]
    public async Task Prefix_longer_than_the_value_and_whole_value_and_trailing_backslash()
    {
        var users = Open();
        await users.AddAsync(U("abc"));
        await users.AddAsync(U(@"ab\"));
        Assert.Empty(await users.ListAsync(usernamePrefix: "abcd"));
        Assert.Equal(["abc"], Names(await users.ListAsync(usernamePrefix: "abc")));
        Assert.Equal([@"ab\"], Names(await users.ListAsync(usernamePrefix: @"ab\")));  // trailing backslash must not break the escape
        Assert.Equal([@"ab\"], Names(await users.ListAsync(usernamePrefix: @"ab\", emailPrefix: @"ab\")));
    }

    [SkippableFact]
    public async Task Usable_without_now_uses_the_store_clock_and_expiry_instant_is_the_boundary()
    {
        var users = Open();
        var at = new DateTimeOffset(2031, 5, 5, 12, 0, 0, TimeSpan.Zero);
        await users.AddAsync(U("one", expires: at));
        Assert.Equal(["one"], Names(await users.ListAsync(usable: false, now: at)));
        Assert.Equal(["one"], Names(await users.ListAsync(usable: true, now: at.AddTicks(-10))));
        Assert.Empty(await users.ListAsync(usable: true, now: at));
        Assert.Equal(["one"], Names(await users.ListAsync(usable: true)));  // 2031 is in the future of the store clock
    }

    [SkippableFact]
    public async Task Paging_with_usable_false_and_prefix_is_stable_across_slices()
    {
        var users = Open();
        for (var i = 0; i < 7; i++) await users.AddAsync(U($"pg-{i}", active: i % 2 == 0));
        var all = Names(await users.ListAsync(usernamePrefix: "pg", usable: false));
        Assert.Equal(["pg-1", "pg-3", "pg-5"], all);
        Assert.Equal(["pg-1", "pg-3"], Names(await users.ListAsync(usernamePrefix: "pg", usable: false, slice: new Slice(0, 2))));
        Assert.Equal(["pg-5"], Names(await users.ListAsync(usernamePrefix: "pg", usable: false, slice: new Slice(2, 2))));
    }
}

public class InMemoryQa8gStoreTests : Qa8gStoreTests
{
    protected override IUserRepository Open() => new InMemoryUserRepository(new InMemoryStore());
}

public class PostgresQa8gStoreTests : Qa8gStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];

    protected override IUserRepository Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return p.GetRequiredService<IUserRepository>();
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }
}
