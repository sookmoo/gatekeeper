using Gatekeeper.Domain;

namespace Gatekeeper.Application;

// List methods return rows ordered deterministically; a Slice (offset, take) pages them. Cancellation
// is honoured where the store supports it.
// Contract for all stores (in-memory now, Postgres later). Uniqueness violations throw
// ConflictException; missing rows yield null/false. Deletes cascade to dependents.
// Writes that reference a parent (role -> app, assignment -> user/role) verify the parent
// atomically with the write and throw NotFoundException if it is gone (FK in Postgres).
// Apps, roles, users and clients carry a version (1 on creation, +1 on every UpdateAsync, whatever the passed entity says).
// UpdateAsync and DeleteAsync take an optional expectedVersion: the write then only happens if the row still has that version,
// decided atomically with the write; otherwise PreconditionFailedException is thrown and nothing changes. A missing row wins
// over a wrong version (null/false), and a version mismatch wins over a uniqueness conflict. Null means unconditional.
// A user also carries SessionsValidAfter (the session cut-off): it only ever rises. UpdateAsync stores max(stored, passed) in the same
// write as the other fields, and writing the cut-off alone (credentials, RevokeAllAndCutOffAsync) never changes the version.

public interface IAppRepository
{
    Task<App> AddAsync(App app, CancellationToken ct = default);
    Task<App?> GetAsync(Guid id, CancellationToken ct = default);
    /// <summary>Case-insensitive.</summary>
    Task<App?> GetByNameAsync(string name, CancellationToken ct = default);
    Task<IReadOnlyList<App>> ListAsync(Slice? slice = null, CancellationToken ct = default);
    Task<App?> UpdateAsync(App app, long? expectedVersion = null, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default);
}

public interface IRoleRepository
{
    Task<Role> AddAsync(Role role, CancellationToken ct = default);
    Task<Role?> GetAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<Role>> ListByAppAsync(Guid appId, Slice? slice = null, CancellationToken ct = default);
    Task<Role?> UpdateAsync(Role role, long? expectedVersion = null, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default);
}

public interface IUserRepository
{
    Task<User> AddAsync(User user, CancellationToken ct = default);
    Task<User?> GetAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<User>> ListAsync(bool? active = null, string? username = null, UserKind? kind = null, Slice? slice = null, CancellationToken ct = default);
    Task<User?> UpdateAsync(User user, long? expectedVersion = null, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default);

    /// <summary>Idempotent. Throws NotFoundException if the user or role does not exist.</summary>
    Task AssignRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default);
    Task<bool> RevokeRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default);
    Task<IReadOnlyList<Role>> ListRolesAsync(Guid userId, Guid? appId = null, Slice? slice = null, CancellationToken ct = default);

    /// <summary>Number of active users holding the role, optionally not counting one user.</summary>
    Task<int> CountActiveWithRoleAsync(Guid roleId, Guid? excludingUserId = null, CancellationToken ct = default);
}

/// <summary>
/// Password hashes live apart from users so they never travel with user DTOs. Cascades with the user.
/// SetAsync is an upsert and throws NotFoundException if the user does not exist.
/// </summary>
public interface ICredentialRepository
{
    /// <summary>
    /// With <paramref name="cutOffAt"/>, in the same atomic write (one transaction under the credential row lock; the version does not change): every active
    /// session of the user is revoked and, as the last write before the commit, the user's session cut-off is raised to at least that time and at least the
    /// store's own clock reading then (so a sign-in stamped after the caller read its clock but before the commit is cut off too). Only when the user already had a password:
    /// a first password raises and revokes nothing (there is nothing to end).
    /// </summary>
    Task SetAsync(Guid userId, string hash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, CancellationToken ct = default);
    Task<string?> GetHashAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Compare-and-set: replaces the hash only if it still equals <paramref name="expectedHash"/>. Returns whether it did. With
    /// <paramref name="cutOffAt"/>, in the same atomic step: every active session of the user except <paramref name="keepSession"/> is revoked, and the cut-off
    /// is raised to at least that time (never lowered). When the cut-off really rises, the kept session (if it is the user's, active and still counts
    /// under the cut-off as it was) is re-stamped to one microsecond after the new cut-off, never to an earlier stamp, so that it alone survives it.
    /// </summary>
    Task<bool> ReplaceHashAsync(Guid userId, string expectedHash, string newHash, DateTimeOffset at, DateTimeOffset? cutOffAt = null, Guid? keepSession = null, CancellationToken ct = default);
}

/// <summary>
/// Service identities. The secret hash is stored apart from the client and never travels with it. A client's
/// application is fixed at creation. Deleting an application, a role or the client removes the dependent rows.
/// </summary>
public interface IClientRepository
{
    /// <summary>Throws ConflictException for a taken name and NotFoundException for an unknown application.</summary>
    Task<Client> AddAsync(Client client, string secretHash, CancellationToken ct = default);
    Task<Client?> GetAsync(Guid id, CancellationToken ct = default);
    /// <summary>Case-insensitive.</summary>
    Task<Client?> GetByNameAsync(string name, CancellationToken ct = default);
    Task<IReadOnlyList<Client>> ListAsync(Guid? appId = null, Slice? slice = null, CancellationToken ct = default);
    /// <summary>Updates name, active flag and timestamp only (and the version).</summary>
    Task<Client?> UpdateAsync(Client client, long? expectedVersion = null, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, long? expectedVersion = null, CancellationToken ct = default);
    Task<bool> SetSecretHashAsync(Guid id, string secretHash, DateTimeOffset at, CancellationToken ct = default);
    Task<string?> GetSecretHashAsync(Guid id, CancellationToken ct = default);

    /// <summary>Idempotent. Throws NotFoundException if the client or role does not exist.</summary>
    Task AssignRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default);
    Task<bool> RevokeRoleAsync(Guid clientId, Guid roleId, CancellationToken ct = default);
    Task<IReadOnlyList<Role>> ListRolesAsync(Guid clientId, Slice? slice = null, CancellationToken ct = default);
}

/// <summary>The hashes of a session's current refresh token and of the one it replaced (kept to detect reuse).</summary>
public sealed record SessionHashes(string Current, string? Previous);

/// <summary>
/// Refresh-token sessions. Rows cascade with the user and the application. Revoking keeps the row (so a replayed old token
/// can still be recognised) until it is purged after it expired.
/// </summary>
public interface ISessionRepository
{
    /// <summary>Throws NotFoundException if the user or application does not exist.</summary>
    Task AddAsync(Session session, string tokenHash, CancellationToken ct = default);
    Task<Session?> GetAsync(Guid id, CancellationToken ct = default);
    Task<SessionHashes?> GetHashesAsync(Guid id, CancellationToken ct = default);
    /// <summary>Newest first; only sessions that are neither revoked nor expired at <paramref name="now"/> and that count after the user's cut-off.</summary>
    Task<IReadOnlyList<Session>> ListActiveByUserAsync(Guid userId, DateTimeOffset now, Slice? slice = null, CancellationToken ct = default);

    /// <summary>
    /// Compare-and-set: if the session is active and its current hash equals <paramref name="expectedHash"/>, make
    /// <paramref name="newHash"/> current (the old one becomes the previous) and record the use. Returns whether it did. A session that no longer
    /// counts after its user's cut-off is not rotated (decided in the same write). The sign-in stamp stays as it is.
    /// </summary>
    Task<bool> RotateAsync(Guid id, string expectedHash, string newHash, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>
    /// As <see cref="AddAsync"/>, but only if the user's stored password hash is still <paramref name="credentialHash"/> (the one the sign-in verified), decided
    /// atomically with the insert: the credential row is read under a share lock held until the insert commits, so a password change either waits for
    /// the insert (and then revokes the session) or commits first (and this returns false, nothing inserted).
    /// </summary>
    Task<bool> AddForCredentialAsync(Session session, string tokenHash, string credentialHash, CancellationToken ct = default);
    /// <summary>Marks the session revoked (idempotent). False if there is no such session.</summary>
    Task<bool> RevokeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Marks the session revoked (idempotent) only if it belongs to the user, in one atomic step. False if there is no such session or it is another user's.</summary>
    Task<bool> RevokeForUserAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Revokes every active session of the user. Returns how many.</summary>
    Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Raises the user's session cut-off to at least <paramref name="now"/> and revokes every active session of the user, in one atomic step. Returns how many rows it revoked (0 for an unknown user).</summary>
    Task<int> RevokeAllAndCutOffAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Revokes every active session of the user except <paramref name="keep"/>. Returns how many.</summary>
    Task<int> RevokeAllForUserExceptAsync(Guid userId, Guid keep, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Revokes every active session of the user in one application. Returns how many.</summary>
    Task<int> RevokeAllForUserInAppAsync(Guid userId, Guid appId, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Shortens active sessions of the user that end after <paramref name="endsAt"/> to end then (never lengthens). Returns how many changed.</summary>
    Task<int> CapExpiryForUserAsync(Guid userId, DateTimeOffset endsAt, DateTimeOffset now, CancellationToken ct = default);
    /// <summary>Deletes sessions that expired before <paramref name="expiredBefore"/>. Returns how many.</summary>
    Task<int> PurgeAsync(DateTimeOffset expiredBefore, CancellationToken ct = default);
}

/// <summary>Append-only: there is deliberately no update or delete. Lists are newest first.</summary>
public interface IAuditRepository
{
    Task AppendAsync(AuditEvent entry, CancellationToken ct = default);
    /// <summary>
    /// Newest first: (At, Id) descending, with ids ordered as <see cref="AuditKey.CompareIds"/> (the Postgres uuid order).
    /// <paramref name="after"/> keeps only rows strictly before that key; <paramref name="take"/> null means all.
    /// </summary>
    Task<IReadOnlyList<AuditEvent>> ListAsync(string? actor = null, string? action = null, AuditKey? after = null, int? take = null, CancellationToken ct = default);
}

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string hash, string password);
    bool NeedsRehash(string hash);
}

/// <summary>Reports whether the backing store is reachable (used by /health/ready).</summary>
public interface IReadinessProbe
{
    Task<bool> IsReadyAsync(CancellationToken ct = default);
}
