using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>QA slice 4a: AuthService behaviour that needs a controllable hasher.</summary>
public class QaAuthServiceTests
{
    /// <summary>Hash = "h:" + password. Every stored value that is not at the "current" version needs rehashing.</summary>
    private sealed class FakeHasher : IPasswordHasher
    {
        public Func<string, Task>? OnHash;
        public int Hashes;
        public string Hash(string password) { Hashes++; OnHash?.Invoke(password).GetAwaiter().GetResult(); return "v2:" + password; }
        public bool Verify(string hash, string password) => hash.EndsWith(":" + password);
        public bool NeedsRehash(string hash) => hash.StartsWith("v1:");
    }

    private static async Task<(InMemoryUserRepository U, ICredentialRepository C, AuthService Auth, FakeHasher H, User User)> Setup()
    {
        var s = new InMemoryStore();
        var apps = new InMemoryAppRepository(s); var roles = new InMemoryRoleRepository(s); var users = new InMemoryUserRepository(s);
        var creds = new InMemoryCredentialRepository(s);
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var role = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "buyer", ""));
        var user = await users.AddAsync(new User(Guid.NewGuid(), "alice", "alice@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        await users.AssignRoleAsync(user.Id, role.Id);
        var h = new FakeHasher();
        return (users, creds, new AuthService(users, apps, creds, h), h, user);
    }

    [Fact]
    public async Task Login_with_an_outdated_hash_upgrades_it_and_still_succeeds()
    {
        var (_, creds, auth, h, user) = await Setup();
        await creds.SetAsync(user.Id, "v1:correct horse battery", DateTimeOffset.UtcNow);
        var r = await auth.LoginAsync("alice", "correct horse battery", "shop");
        Assert.NotNull(r);
        Assert.Equal("v2:correct horse battery", await creds.GetHashAsync(user.Id));
        Assert.True((await auth.LoginAsync("ALICE", "correct horse battery", "SHOP")) is not null);
    }

    [Fact]
    public async Task Failed_logins_never_rehash_or_alter_the_stored_hash()
    {
        var (users, creds, auth, _, user) = await Setup();
        await creds.SetAsync(user.Id, "v1:correct horse battery", DateTimeOffset.UtcNow);
        Assert.Null(await auth.LoginAsync("alice", "wrong password here", "shop"));
        Assert.Null(await auth.LoginAsync("alice", "correct horse battery", "nope"));
        await users.UpdateAsync(user with { IsActive = false });
        Assert.Null(await auth.LoginAsync("alice", "correct horse battery", "shop"));
        Assert.Equal("v1:correct horse battery", await creds.GetHashAsync(user.Id));
    }

    [Fact]
    public async Task Rehash_on_login_must_not_overwrite_a_password_changed_meanwhile()
    {
        // Scenario: the old password is verified, then an administrator sets a new password while the login is
        // re-hashing. The login must not write the old password's hash back over the new one.
        var (_, creds, auth, h, user) = await Setup();
        await creds.SetAsync(user.Id, "v1:old password here", DateTimeOffset.UtcNow);
        h.OnHash = async pw =>
        {
            if (pw == "old password here")
                await creds.SetAsync(user.Id, "v2:brand new password", DateTimeOffset.UtcNow); // concurrent PUT /password
        };
        Assert.NotNull(await auth.LoginAsync("alice", "old password here", "shop"));
        Assert.Equal("v2:brand new password", await creds.GetHashAsync(user.Id));
    }

    [Fact]
    public async Task Unknown_user_and_unknown_app_still_cost_one_hash_verification()
    {
        var (_, creds, auth, h, user) = await Setup();
        await creds.SetAsync(user.Id, "v2:correct horse battery", DateTimeOffset.UtcNow);
        var before = h.Hashes;
        Assert.Null(await auth.LoginAsync("ghost", "correct horse battery", "shop"));
        Assert.Null(await auth.LoginAsync("alice", "correct horse battery", "ghost-app"));
        Assert.Null(await auth.LoginAsync(null, null, null));
        Assert.True(h.Hashes <= before + 1); // only the lazily created dummy hash; no per-attempt hashing of the candidate
    }

    [Fact]
    public async Task Cancelled_login_throws_cancellation_not_a_null_result()
    {
        var (_, creds, auth, _, user) = await Setup();
        await creds.SetAsync(user.Id, "v2:correct horse battery", DateTimeOffset.UtcNow);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var ex = await Record.ExceptionAsync(() => auth.LoginAsync("alice", "correct horse battery", "shop", cts.Token));
        Assert.IsAssignableFrom<OperationCanceledException>(ex);
    }

    [Fact]
    public async Task User_with_more_than_200_roles_in_the_application_gets_all_of_them()
    {
        var s = new InMemoryStore();
        var apps = new InMemoryAppRepository(s); var roles = new InMemoryRoleRepository(s); var users = new InMemoryUserRepository(s);
        var creds = new InMemoryCredentialRepository(s);
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "big"));
        var user = await users.AddAsync(new User(Guid.NewGuid(), "many", "many@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        for (var i = 0; i < 250; i++)
            await users.AssignRoleAsync(user.Id, (await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, $"r{i:D3}", ""))).Id);
        var h = new FakeHasher();
        await creds.SetAsync(user.Id, "v2:correct horse battery", DateTimeOffset.UtcNow);
        var r = await new AuthService(users, apps, creds, h).LoginAsync("many", "correct horse battery", "big");
        Assert.Equal(250, r!.Roles.Count);
    }

    // ---- slice 6f: sign-in to the reserved application without a role there ----

    private static async Task<(AuthService Auth, InMemoryUserRepository Users, IAppRepository Apps, ICredentialRepository Creds)> Reserved6f()
    {
        var s = new InMemoryStore();
        var apps = new InMemoryAppRepository(s); var users = new InMemoryUserRepository(s); var creds = new InMemoryCredentialRepository(s);
        await apps.AddAsync(new App(Guid.NewGuid(), "gatekeeper"));
        await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        return (new AuthService(users, apps, creds, new FakeHasher()), users, apps, creds);
    }

    private static async Task<User> AddUser(InMemoryUserRepository users, ICredentialRepository creds, string name, UserKind kind, bool active = true, DateTimeOffset? expires = null)
    {
        var u = await users.AddAsync(new User(Guid.NewGuid(), name, $"{name}@example.com", "", active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, kind, expires));
        await creds.SetAsync(u.Id, "v2:correct horse battery", DateTimeOffset.UtcNow);
        return u;
    }

    [Fact]
    public async Task Person_and_test_users_sign_in_to_the_reserved_app_without_roles_but_not_elsewhere()
    {
        var (auth, users, _, creds) = await Reserved6f();
        var person = await AddUser(users, creds, "alice", UserKind.Person);
        var test = await AddUser(users, creds, "tess", UserKind.Test, expires: DateTimeOffset.UtcNow.AddDays(1));
        foreach (var name in new[] { "alice", "tess" })
        {
            var r = await auth.LoginAsync(name, "correct horse battery", "gatekeeper");
            Assert.NotNull(r);
            Assert.Empty(r!.Roles);
            Assert.Null(await auth.LoginAsync(name, "correct horse battery", "shop"));
        }
        var gatekeeper = (await auth.LoginAsync("alice", "correct horse battery", "gatekeeper"))!.App;
        Assert.NotNull(await auth.ResolveAsync(person.Id, gatekeeper.Id));
        Assert.Null(await auth.ResolveAsync(person.Id, Guid.NewGuid()));
        _ = test;
    }

    [Fact]
    public async Task Shared_disabled_expired_and_wrongly_authenticated_users_still_get_nothing()
    {
        var (auth, users, apps, creds) = await Reserved6f();
        var shared = await AddUser(users, creds, "team", UserKind.Shared);
        var off = await AddUser(users, creds, "off", UserKind.Person, active: false);
        var gone = await AddUser(users, creds, "gone", UserKind.Test, expires: DateTimeOffset.UtcNow.AddSeconds(-5));
        var ok = await AddUser(users, creds, "ok", UserKind.Person);
        Assert.Null(await auth.LoginAsync("team", "correct horse battery", "gatekeeper"));
        Assert.Null(await auth.LoginAsync("off", "correct horse battery", "gatekeeper"));
        Assert.Null(await auth.LoginAsync("gone", "correct horse battery", "gatekeeper"));
        Assert.Null(await auth.LoginAsync("ok", "wrong password entirely", "gatekeeper"));
        var gatekeeper = (await apps.GetByNameAsync("gatekeeper"))!;
        Assert.Null(await auth.ResolveAsync(shared.Id, gatekeeper.Id));
        Assert.Null(await auth.ResolveAsync(off.Id, gatekeeper.Id));
        Assert.Null(await auth.ResolveAsync(gone.Id, gatekeeper.Id));
        Assert.NotNull(await auth.ResolveAsync(ok.Id, gatekeeper.Id));
    }
}
