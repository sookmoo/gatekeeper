namespace Gatekeeper.Domain;

/// <summary>
/// A row that carries a version for optimistic concurrency. It starts at 1 and the store adds 1 on every write of the row's own
/// fields (not on role assignments, passwords, secrets or sessions, which are separate resources). The API exposes it as the
/// body field <c>version</c> and the strong ETag <c>"&lt;version&gt;"</c>.
/// </summary>
public interface IVersioned
{
    long Version { get; }
}

public sealed record App(Guid Id, string Name, long Version = 1) : IVersioned;

public sealed record Role(Guid Id, Guid AppId, string Name, string Description, long Version = 1) : IVersioned;

public sealed record User(
    Guid Id,
    string Username,
    string Email,
    string DisplayName,
    bool IsActive,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    UserKind Kind = UserKind.Person,
    DateTimeOffset? ExpiresAt = null,
    long Version = 1) : IVersioned
{
    /// <summary>Whether the account may sign in right now: enabled and, for a test user, not past its expiry.</summary>
    public bool IsUsable(DateTimeOffset now) => IsActive && (ExpiresAt is null || ExpiresAt > now);
}

/// <summary>
/// What a user account stands for. Only a person can be an administrator. A test account must expire.
/// Service identities are a separate entity (<see cref="Client"/>), not a kind of user.
/// </summary>
public enum UserKind
{
    /// <summary>A real person.</summary>
    Person,
    /// <summary>A non-personal account for testing. Always has an expiry date.</summary>
    Test,
    /// <summary>A non-personal account that several people or a team use (for example a shared mailbox login).</summary>
    Shared,
}

/// <summary>
/// A service identity: an external system that authenticates with a secret (no password, no person) and receives a token
/// for exactly one application, carrying the roles assigned to it. It can never belong to the reserved admin application.
/// </summary>
public sealed record Client(
    Guid Id,
    string Name,
    Guid AppId,
    bool IsActive,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    long Version = 1) : IVersioned;

/// <summary>
/// A refresh-token session of a user in one application. The token hashes live in the store, never on this record.
/// A session is usable while it is neither revoked nor past <see cref="ExpiresAt"/> (an absolute limit; rotation does not extend it).
/// </summary>
public sealed record Session(
    Guid Id,
    Guid UserId,
    Guid AppId,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastUsedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt)
{
    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
}
