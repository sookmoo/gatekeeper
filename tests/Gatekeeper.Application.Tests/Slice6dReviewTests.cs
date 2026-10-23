using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

/// <summary>Slice 6d review: a user PATCH writes onto the version it read, and a PATCH that changes nothing writes nothing.</summary>
public class Slice6dReviewTests
{
    /// <summary>Runs a hook once after the first read (deterministic interleaving, no sleeping).</summary>
    private sealed class AfterFirstGet(IUserRepository inner) : IUserRepository
    {
        public Func<Task>? Hook;
        public async Task<User?> GetAsync(Guid id, CancellationToken ct = default)
        {
            var u = await inner.GetAsync(id, ct);
            if (Hook is { } h) { Hook = null; await h(); }
            return u;
        }
        public Task<User> AddAsync(User user, CancellationToken ct = default) => inner.AddAsync(user, ct);
        public Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, UserKind? kind = null, Slice? slice = null, CancellationToken ct = default) => inner.ListAsync(active, username, kind, slice, ct);
        public Task<User?> UpdateAsync(User user, long? expectedVersion = null, CancellationToken ct = default) => inner.UpdateAsync(user, expectedVersion, ct);
        public Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default) => inner.DeleteAsync(id, expectedVersion, ct);
        public Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default) => inner.AssignRoleAsync(userId, roleId, ct);
        public Task<bool> RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default) => inner.RevokeRoleAsync(userId, roleId, ct);
        public Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null, Slice? slice = null, CancellationToken ct = default) => inner.ListRolesAsync(userId, appId, slice, ct);
        public Task<int> CountActiveWithRoleAsync(Guid roleId, Guid? excludingUserId = null, CancellationToken ct = default) => inner.CountActiveWithRoleAsync(roleId, excludingUserId, ct);
    }

    [Fact]
    public async Task A_patch_with_several_tags_is_pinned_to_the_version_it_read()
    {
        var store = new InMemoryStore();
        var users = new InMemoryUserRepository(store);
        var hooked = new AfterFirstGet(users);
        var svc = new UserService(hooked);
        var u = await svc.CreateAsync("alice", "alice@example.com", "A");
        await svc.UpdateAsync(u.Id, "alice", "alice@example.com", "B", null);
        await svc.UpdateAsync(u.Id, "alice", "alice@example.com", "C", null); // version 3
        Assert.Equal(3, (await svc.GetAsync(u.Id)).Version);

        // an interleaved PUT moves the row to version 4 right after the PATCH read version 3; "4" is also in the header
        hooked.Hook = () => svc.UpdateAsync(u.Id, "alice", "alice@example.com", "PUT-wins", null);
        await Assert.ThrowsAsync<PreconditionFailedException>(() =>
            svc.PatchAsync(u.Id, null, null, "PATCH-loses", null, ifMatch: Precondition.Parse("\"3\", \"4\"")));
        var now = await svc.GetAsync(u.Id);
        Assert.Equal(("PUT-wins", 4), (now.DisplayName, now.Version));

        // without the interleaving the same header works and bumps once
        var patched = await svc.PatchAsync(u.Id, null, null, "D", null, ifMatch: Precondition.Parse("\"3\", \"4\""));
        Assert.Equal(("D", 5), (patched.DisplayName, patched.Version));
    }

    [Fact]
    public async Task A_patch_that_changes_nothing_writes_nothing_but_still_checks_the_precondition()
    {
        var svc = new UserService(new InMemoryUserRepository(new InMemoryStore()));
        var u = await svc.CreateAsync("alice", "alice@example.com", "A");
        var same = await svc.PatchAsync(u.Id, null, "alice@example.com", "A", true);
        Assert.Equal((1, u.UpdatedAt), (same.Version, same.UpdatedAt));
        await Assert.ThrowsAsync<PreconditionFailedException>(() => svc.PatchAsync(u.Id, null, null, null, null, ifMatch: Precondition.Parse("\"9\"")));
        Assert.Equal(1, (await svc.PatchAsync(u.Id, null, null, null, null, ifMatch: Precondition.Parse("\"1\""))).Version);
        Assert.Equal(2, (await svc.PatchAsync(u.Id, null, null, "B", null)).Version);
    }
}
