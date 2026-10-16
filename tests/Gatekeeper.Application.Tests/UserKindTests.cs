using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>User kinds (person, test, shared), test-user expiry and the rule that only a person may be an administrator.</summary>
public class UserKindTests
{
    private sealed class PlainHasher : IPasswordHasher
    {
        public string Hash(string password) => "h:" + password;
        public bool Verify(string hash, string password) => hash == "h:" + password;
        public bool NeedsRehash(string hash) => false;
    }

    private sealed record Rig(UserService Users, AuthService Auth, ICredentialRepository Creds, Guid AdminRole, Guid ShopRole)
    {
        public InMemoryUserRepository Repo { get; init; } = null!;
    }

    private static async Task<Rig> Setup()
    {
        var s = new InMemoryStore();
        var apps = new InMemoryAppRepository(s); var roles = new InMemoryRoleRepository(s); var users = new InMemoryUserRepository(s);
        var creds = new InMemoryCredentialRepository(s);
        var gk = await apps.AddAsync(new App(Guid.NewGuid(), Reserved.AdminApp));
        var admin = await roles.AddAsync(new Role(Guid.NewGuid(), gk.Id, Reserved.AdminRole, ""));
        var shop = await apps.AddAsync(new App(Guid.NewGuid(), "shop"));
        var buyer = await roles.AddAsync(new Role(Guid.NewGuid(), shop.Id, "buyer", ""));
        var guard = new AdminGuard(apps, roles, users);
        return new Rig(new UserService(users, guard), new AuthService(users, apps, creds, new PlainHasher()), creds, admin.Id, buyer.Id) { Repo = users };
    }

    private static Task<User> Make(Rig r, string name, UserKind kind = UserKind.Person, DateTimeOffset? expires = null) =>
        r.Users.CreateAsync(name, $"{name}@example.com", null, true, kind, expires);

    [Fact]
    public async Task A_user_is_a_person_by_default_and_has_no_expiry()
    {
        var r = await Setup();
        var u = await r.Users.CreateAsync("alice", "alice@example.com", null);
        Assert.Equal(UserKind.Person, u.Kind);
        Assert.Null(u.ExpiresAt);
    }

    [Fact]
    public async Task A_test_user_without_a_date_expires_after_the_default_lifetime()
    {
        var r = await Setup();
        var before = DateTimeOffset.UtcNow;
        var u = await Make(r, "tester", UserKind.Test);
        Assert.InRange(u.ExpiresAt!.Value, before + Validation.DefaultTestLifetime, DateTimeOffset.UtcNow + Validation.DefaultTestLifetime);
    }

    [Fact]
    public async Task Expiry_is_stored_to_the_microsecond_so_both_stores_return_what_was_given()
    {
        var r = await Setup();
        var u = await Make(r, "tester", UserKind.Test, DateTimeOffset.UtcNow.AddDays(2).AddTicks(7));
        Assert.Equal(0, u.ExpiresAt!.Value.Ticks % 10);
    }

    [Fact]
    public async Task Invalid_expiries_and_kinds_are_refused()
    {
        var r = await Setup();
        await Assert.ThrowsAsync<ValidationException>(() => Make(r, "a1", UserKind.Test, DateTimeOffset.UtcNow.AddMinutes(-1)));
        await Assert.ThrowsAsync<ValidationException>(() => Make(r, "a2", UserKind.Test, DateTimeOffset.UtcNow.AddDays(400)));
        await Assert.ThrowsAsync<ValidationException>(() => Make(r, "a3", UserKind.Person, DateTimeOffset.UtcNow.AddDays(1)));
        await Assert.ThrowsAsync<ValidationException>(() => Make(r, "a4", UserKind.Shared, DateTimeOffset.UtcNow.AddDays(1)));
        await Assert.ThrowsAsync<ValidationException>(() => Make(r, "a5", (UserKind)7));
    }

    [Fact]
    public async Task Turning_a_person_into_a_test_user_gives_it_an_expiry_and_back_removes_it()
    {
        var r = await Setup();
        var u = await Make(r, "alice");
        var test = await r.Users.PatchAsync(u.Id, null, null, null, null, UserKind.Test);
        Assert.Equal(UserKind.Test, test.Kind);
        Assert.NotNull(test.ExpiresAt);
        var back = await r.Users.PatchAsync(u.Id, null, null, null, null, UserKind.Person);
        Assert.Null(back.ExpiresAt);
        // a date for a person is refused
        await Assert.ThrowsAsync<ValidationException>(() => r.Users.PatchAsync(u.Id, null, null, null, null, null, DateTimeOffset.UtcNow.AddDays(1)));
    }

    [Fact]
    public async Task Renaming_a_test_user_keeps_its_expiry_and_a_new_date_replaces_it()
    {
        var r = await Setup();
        var when = DateTimeOffset.UtcNow.AddDays(10);
        var u = await Make(r, "tester", UserKind.Test, when);
        var renamed = await r.Users.PatchAsync(u.Id, null, null, "Tester One", null);
        Assert.Equal(u.ExpiresAt, renamed.ExpiresAt);
        var later = await r.Users.PatchAsync(u.Id, null, null, null, null, null, DateTimeOffset.UtcNow.AddDays(20));
        Assert.True(later.ExpiresAt > renamed.ExpiresAt);
        var put = await r.Users.UpdateAsync(u.Id, "tester", "tester@example.com", "", null); // full replace without a date keeps it
        Assert.Equal(later.ExpiresAt, put.ExpiresAt);
    }

    [Fact]
    public async Task Only_a_person_can_be_given_the_admin_role()
    {
        var r = await Setup();
        foreach (var kind in new[] { UserKind.Test, UserKind.Shared })
        {
            var u = await Make(r, $"np-{kind}".ToLowerInvariant(), kind, kind == UserKind.Test ? DateTimeOffset.UtcNow.AddDays(1) : null);
            await Assert.ThrowsAsync<ConflictException>(() => r.Users.AssignRoleAsync(u.Id, r.AdminRole));
            await r.Users.AssignRoleAsync(u.Id, r.ShopRole); // any other role is fine
        }
        var person = await Make(r, "alice");
        await r.Users.AssignRoleAsync(person.Id, r.AdminRole);
    }

    [Fact]
    public async Task An_administrator_cannot_become_a_non_person_until_the_role_is_revoked()
    {
        var r = await Setup();
        var a = await Make(r, "alice"); var b = await Make(r, "bob");
        await r.Users.AssignRoleAsync(a.Id, r.AdminRole);
        await r.Users.AssignRoleAsync(b.Id, r.AdminRole);
        await Assert.ThrowsAsync<ConflictException>(() => r.Users.PatchAsync(a.Id, null, null, null, null, UserKind.Shared));
        Assert.Equal(UserKind.Person, (await r.Users.GetAsync(a.Id)).Kind);
        await r.Users.RevokeRoleAsync(a.Id, r.AdminRole);
        Assert.Equal(UserKind.Shared, (await r.Users.PatchAsync(a.Id, null, null, null, null, UserKind.Shared)).Kind);
    }

    [Fact]
    public async Task List_can_filter_by_kind()
    {
        var r = await Setup();
        await Make(r, "alice"); await Make(r, "tester", UserKind.Test); await Make(r, "team", UserKind.Shared);
        Assert.Equal(["tester"], (await r.Users.ListAsync(kind: UserKind.Test)).Items.Select(u => u.Username));
        Assert.Equal(["team"], (await r.Users.ListAsync(kind: UserKind.Shared)).Items.Select(u => u.Username));
        Assert.Equal(3, (await r.Users.ListAsync()).Items.Count);
        Assert.Empty((await r.Users.ListAsync(kind: (UserKind)9)).Items);
    }

    [Fact]
    public async Task An_expired_test_user_can_no_longer_sign_in_or_be_resolved()
    {
        var r = await Setup();
        var u = await Make(r, "tester", UserKind.Test, DateTimeOffset.UtcNow.AddDays(1));
        await r.Users.AssignRoleAsync(u.Id, r.ShopRole);
        await r.Creds.SetAsync(u.Id, "h:correct horse battery", DateTimeOffset.UtcNow);
        Assert.NotNull(await r.Auth.LoginAsync("tester", "correct horse battery", "shop"));
        // The expiry passes (set directly: the service refuses dates in the past).
        await r.Repo.UpdateAsync(u with { Kind = UserKind.Test, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) });
        Assert.Null(await r.Auth.LoginAsync("tester", "correct horse battery", "shop"));
        var app = (await r.Repo.ListRolesAsync(u.Id)).First().AppId;
        Assert.Null(await r.Auth.ResolveAsync(u.Id, app));
    }
}
