using Gatekeeper.Application;
using Microsoft.Extensions.Caching.Memory;

namespace Gatekeeper.Api;

/// <summary>
/// Access tokens live 15 minutes, so on every management request the token's subject is re-checked against the store:
/// still active and still holding the admin role. The answer is cached for a few seconds, which bounds how long a
/// demoted or deactivated administrator keeps working.
/// </summary>
public sealed class AdminAccessCheck(IUserRepository users, AdminGuard guard, IMemoryCache cache)
{
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(10);

    public Task<bool> IsAdminAsync(Guid userId, CancellationToken ct) =>
        cache.GetOrCreateAsync(("admin", userId), async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheFor;
            if (await users.GetAsync(userId, ct) is not { IsActive: true }) return false;
            if (await guard.AdminRoleIdAsync(ct) is not { } adminRole) return false;
            return (await users.ListRolesAsync(userId, slice: new Slice(0, 10_000), ct: ct)).Any(r => r.Id == adminRole);
        })!;
}
