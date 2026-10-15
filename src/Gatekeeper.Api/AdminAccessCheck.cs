using Gatekeeper.Application;
using Microsoft.Extensions.Caching.Memory;

namespace Gatekeeper.Api;

/// <summary>
/// Access tokens live 15 minutes, so on every management request the token's subject is re-checked against the store:
/// still active and still holding the admin role. The answer is cached for a few seconds, which bounds how long a
/// demoted or deactivated administrator keeps working.
/// </summary>
public sealed class AdminAccessCheck(IUserRepository users, AdminGuard guard, IMemoryCache cache, SessionService sessions)
{
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(10);

    /// <param name="sessionId">The token's sid, if it came from a refresh session: a revoked or expired session ends the token.</param>
    public Task<bool> IsAdminAsync(Guid userId, Guid? sessionId, CancellationToken ct) =>
        cache.GetOrCreateAsync(("admin", userId, sessionId), async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheFor;
            if (sessionId is { } sid && !await sessions.IsActiveAsync(sid, ct)) return false;
            if (await users.GetAsync(userId, ct) is not { } user || !user.IsUsable(DateTimeOffset.UtcNow)) return false;
            if (await guard.AdminRoleIdAsync(ct) is not { } adminRole) return false;
            return (await users.ListRolesAsync(userId, slice: new Slice(0, 10_000), ct: ct)).Any(r => r.Id == adminRole);
        })!;
}
