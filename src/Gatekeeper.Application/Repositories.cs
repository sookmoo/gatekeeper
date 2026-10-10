using Gatekeeper.Domain;

namespace Gatekeeper.Application;

// Contract for all stores (in-memory now, Postgres later). Uniqueness violations throw
// ConflictException; missing rows yield null/false. Deletes cascade to dependents.
// Writes that reference a parent (role -> app, assignment -> user/role) verify the parent
// atomically with the write and throw NotFoundException if it is gone (FK in Postgres).

public interface IAppRepository
{
    Task<App> AddAsync(App app);
    Task<App?> GetAsync(Guid id);
    Task<IReadOnlyList<App>> ListAsync();
    Task<App?> UpdateAsync(App app);
    Task<bool> DeleteAsync(Guid id);
}

public interface IRoleRepository
{
    Task<Role> AddAsync(Role role);
    Task<Role?> GetAsync(Guid id);
    Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId);
    Task<Role?> UpdateAsync(Role role);
    Task<bool> DeleteAsync(Guid id);
}

public interface IUserRepository
{
    Task<User> AddAsync(User user);
    Task<User?> GetAsync(Guid id);
    Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null);
    Task<User?> UpdateAsync(User user);
    Task<bool> DeleteAsync(Guid id);

    /// <summary>Idempotent. Throws NotFoundException if the user or role does not exist.</summary>
    Task AssignRoleAsync(Guid userId, Guid roleId);
    Task<bool> RevokeRoleAsync(Guid userId, Guid roleId);
    Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null);
}
