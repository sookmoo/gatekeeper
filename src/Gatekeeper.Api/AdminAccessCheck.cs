using Gatekeeper.Domain;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;

namespace Gatekeeper.Api;

/// <summary>What the store says about a token's subject right now (a usable user whose session, if any, is still active).</summary>
public sealed record AccessState(UserKind Kind, bool IsAdmin);

/// <summary>
/// Access tokens live 15 minutes, so on every request the token's subject is re-checked against the store: still usable
/// (active, not expired), session still active, and whether it still holds the admin role. The answer is cached for a few
/// seconds, which bounds how long a demoted or deactivated administrator keeps working.
/// </summary>
public sealed class AdminAccessCheck(IUserRepository users, AdminGuard guard, IMemoryCache cache, SessionService sessions)
{
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(10);

    /// <param name="sessionId">The token's sid, if it came from a refresh session: a revoked or expired session ends the token.</param>
    /// <returns>Null when the user is gone, disabled or expired, or the session has ended.</returns>
    public Task<AccessState?> StateAsync(Guid userId, Guid? sessionId, CancellationToken ct) =>
        cache.GetOrCreateAsync(("access", userId, sessionId), async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheFor;
            // Linked to a per-user token so Evict(userId) drops every entry of the user at once. The token entry is sliding and touched by
            // every creation here, so it outlives all the (10 s) entries that depend on it.
            var generation = cache.GetOrCreate(("access-gen", userId), e =>
            {
                e.SlidingExpiration = TimeSpan.FromSeconds(30);
                return new CancellationTokenSource();
            })!;
            entry.AddExpirationToken(new Microsoft.Extensions.Primitives.CancellationChangeToken(generation.Token));
            if (sessionId is { } sid && !await sessions.IsActiveAsync(sid, ct)) return null;
            if (await users.GetAsync(userId, ct) is not { } user || !user.IsUsable(Clock.UtcNowMicros())) return null;
            // Only a person administers Gatekeeper, whatever the role table says.
            var admin = user.Kind == UserKind.Person && await guard.AdminRoleIdAsync(ct) is { } adminRole
                        && (await users.ListRolesAsync(userId, slice: new Slice(0, 10_000), ct: ct)).Any(r => r.Id == adminRole);
            return (AccessState?)new AccessState(user.Kind, admin);
        })!;

    /// <summary>Forgets the cached answer for a session that was just ended, so its tokens stop at once on this instance.</summary>
    public void Evict(Guid userId, Guid? sessionId) => cache.Remove(("access", userId, sessionId));

    /// <summary>Forgets every cached answer for the user (all sessions), so their tokens are re-checked against the store at once on this instance.</summary>
    public void Evict(Guid userId)
    {
        if (cache.TryGetValue(("access-gen", userId), out CancellationTokenSource? generation) && generation is not null)
        {
            cache.Remove(("access-gen", userId));
            generation.Cancel();
        }
    }

    /// <summary>The token's subject and session, or null when the claims are malformed.</summary>
    public static (Guid UserId, Guid? SessionId)? Subject(System.Security.Claims.ClaimsPrincipal principal)
    {
        Guid? sessionId = null;
        if (principal.FindFirst(TokenService.SessionClaim)?.Value is { } sidText)
        {
            if (!Guid.TryParse(sidText, out var sid)) return null;
            sessionId = sid;
        }
        return Guid.TryParse(principal.FindFirst("sub")?.Value, out var userId) ? (userId, sessionId) : null;
    }
}

/// <summary>The management API: the token carries the admin role AND the store still says so (403 otherwise, so a self token is refused, not unauthenticated).</summary>
public sealed class AdminRequirement : IAuthorizationRequirement;

/// <summary>/v1/me: a usable person or test user, whatever roles it holds. Shared accounts get no self-service.</summary>
public sealed class SelfRequirement : IAuthorizationRequirement;

public sealed class AccessHandler(AdminAccessCheck access) : IAuthorizationHandler
{
    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        var ct = (context.Resource as HttpContext)?.RequestAborted ?? CancellationToken.None;
        foreach (var requirement in context.PendingRequirements.ToList())
        {
            if (requirement is not (AdminRequirement or SelfRequirement)) continue;
            if (context.User.Identity?.IsAuthenticated != true || AdminAccessCheck.Subject(context.User) is not var (userId, sid)
                || await access.StateAsync(userId, sid, ct) is not { } state) continue;
            var ok = requirement is AdminRequirement
                ? state.IsAdmin && context.User.IsInRole(Reserved.AdminRole)
                : state.Kind is UserKind.Person or UserKind.Test;
            if (ok) context.Succeed(requirement);
        }
    }
}
