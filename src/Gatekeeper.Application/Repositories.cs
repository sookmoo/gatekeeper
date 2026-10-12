using Gatekeeper.Domain;

namespace Gatekeeper.Application;

// List methods return rows ordered deterministically; a Slice (offset, take) pages them. Cancellation
// is honoured where the store supports it.
// Contract for all stores (in-memory now, Postgres later). Uniqueness violations throw
// ConflictException; missing rows yield null/false. Deletes cascade to dependents.
// Writes that reference a parent (role -> app, assignment -> user/role) verify the parent
// atomically with the write and throw NotFoundException if it is gone (FK in Postgres).

public interface IAppRepository
{
    Task<App> AddAsync(App app, CancellationToken ct = default);
    Task<App?> GetAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<App>> ListAsync(Slice? slice = null, CancellationToken ct = default);
    Task<App?> UpdateAsync(App app, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);
}

public interface IRoleRepository
{
    Task<Role> AddAsync(Role role, CancellationToken ct = default);
    Task<Role?> GetAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId, Slice? slice = null, CancellationToken ct = default);
    Task<Role?> UpdateAsync(Role role, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);
}

public interface IUserRepository
{
    Task<User> AddAsync(User user, CancellationToken ct = default);
    Task<User?> GetAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, Slice? slice = null, CancellationToken ct = default);
    Task<User?> UpdateAsync(User user, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);

    /// <summary>Idempotent. Throws NotFoundException if the user or role does not exist.</summary>
    Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default);
    Task<bool> RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default);
    Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null, Slice? slice = null, CancellationToken ct = default);
}

/// <summary>Reports whether the backing store is reachable (used by /health/ready).</summary>
public interface IReadinessProbe
{
    Task<bool> IsReadyAsync(CancellationToken ct = default);
}
