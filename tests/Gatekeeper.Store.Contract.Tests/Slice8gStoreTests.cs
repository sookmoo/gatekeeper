using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Slice 8g: prefix search and the "usable" filter of the user list, run against both stores.</summary>
public abstract class Slice8gStoreTests : IDisposable
{
    protected abstract IUserRepository Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static readonly DateTimeOffset Now = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static User U(string name, string? email = null, bool active = true, DateTimeOffset? expires = null) =>
        new(Guid.NewGuid(), name, email ?? $"{name}@example.com", name, active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            expires is null ? UserKind.Person : UserKind.Test, expires);

    private static string[] Names(IReadOnlyList<User> l) => [.. l.Select(u => u.Username)];

    [SkippableFact]
    public async Task Username_prefix_is_case_insensitive_and_literal()
    {
        var users = Open();
        // Names the service would refuse are stored directly, to prove that %, _ and \ in the search text are not wildcards.
        foreach (var n in new[] { "alice", "alina", "al%x", "al_x", "alxx", @"al\x", "bob" }) await users.AddAsync(U(n));
        Assert.Equal(new[] { "alice", "alina", "alxx", "al%x", "al_x", @"al\x" }.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            Names(await users.ListAsync(usernamePrefix: "al")).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
        Assert.Equal(["alice", "alina"], Names(await users.ListAsync(usernamePrefix: "ALI")).Order().ToArray());
        Assert.Equal(["alice"], Names(await users.ListAsync(usernamePrefix: "AliCe")));
        Assert.Equal(["al%x"], Names(await users.ListAsync(usernamePrefix: "al%")));
        Assert.Equal(["al_x"], Names(await users.ListAsync(usernamePrefix: "al_")));
        Assert.Equal([@"al\x"], Names(await users.ListAsync(usernamePrefix: @"al\")));
        Assert.Empty(await users.ListAsync(usernamePrefix: "%l"));   // a wildcard at the start matches nothing
        Assert.Empty(await users.ListAsync(usernamePrefix: "__"));
        Assert.Empty(await users.ListAsync(usernamePrefix: @"\\"));
        Assert.Empty(await users.ListAsync(usernamePrefix: "lice")); // a prefix, not a substring
    }

    [SkippableFact]
    public async Task Email_prefix_is_case_insensitive_and_literal()
    {
        var users = Open();
        await users.AddAsync(U("u1", "Zed.One@example.com"));
        await users.AddAsync(U("u2", "zed_two@example.com"));
        await users.AddAsync(U("u3", "zedxtwo@example.com"));
        Assert.Equal(["u1", "u2", "u3"], Names(await users.ListAsync(emailPrefix: "ZED")));
        Assert.Equal(["u2"], Names(await users.ListAsync(emailPrefix: "zed_")));
        Assert.Equal(["u1"], Names(await users.ListAsync(emailPrefix: "zed.o")));
        Assert.Empty(await users.ListAsync(emailPrefix: "%"));
        Assert.Empty(await users.ListAsync(emailPrefix: "example.com"));
    }

    [SkippableFact]
    public async Task Usable_means_enabled_and_not_expired()
    {
        var users = Open();
        await users.AddAsync(U("person"));                                             // usable
        await users.AddAsync(U("fresh", expires: Now.AddDays(1)));                    // usable
        await users.AddAsync(U("stale", expires: Now.AddDays(-1)));                   // expired
        await users.AddAsync(U("edge", expires: Now));                                // expires exactly now: expired
        await users.AddAsync(U("off", active: false));                                // disabled
        await users.AddAsync(U("offstale", active: false, expires: Now.AddDays(-1))); // both
        Assert.Equal(["fresh", "person"], Names(await users.ListAsync(usable: true, now: Now)));
        Assert.Equal(["edge", "off", "offstale", "stale"], Names(await users.ListAsync(usable: false, now: Now)));
        // active= is unchanged: it still includes expired test users
        Assert.Equal(["edge", "fresh", "person", "stale"], Names(await users.ListAsync(active: true)));
        Assert.Equal(["fresh"], Names(await users.ListAsync(active: true, usable: true, usernamePrefix: "fr", now: Now)));
        Assert.Empty(await users.ListAsync(active: false, usable: true, now: Now));
    }

    [SkippableFact]
    public async Task Filters_combine_and_page_correctly()
    {
        var users = Open();
        for (var i = 0; i < 9; i++) await users.AddAsync(U($"team-{i}", $"t{i}@corp.test", active: i % 3 != 0));
        await users.AddAsync(U("team-x", "x@other.test"));
        await users.AddAsync(U("other-1", "t1@other.test"));
        var all = Names(await users.ListAsync(usernamePrefix: "team-", emailPrefix: "t", usable: true, now: Now));
        Assert.Equal(["team-1", "team-2", "team-4", "team-5", "team-7", "team-8"], all);
        Assert.Equal(["team-1", "team-2", "team-4"], Names(await users.ListAsync(usernamePrefix: "team-", emailPrefix: "t", usable: true, now: Now, slice: new Slice(0, 3))));
        Assert.Equal(["team-5", "team-7", "team-8"], Names(await users.ListAsync(usernamePrefix: "team-", emailPrefix: "t", usable: true, now: Now, slice: new Slice(3, 3))));
        Assert.Empty(await users.ListAsync(usernamePrefix: "team-", emailPrefix: "zz", usable: true, now: Now));
    }
}

public class InMemorySlice8gStoreTests : Slice8gStoreTests
{
    protected override IUserRepository Open() => new InMemoryUserRepository(new InMemoryStore());
}

public class PostgresSlice8gStoreTests : Slice8gStoreTests
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
