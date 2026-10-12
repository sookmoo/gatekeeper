namespace Gatekeeper.Domain;

public sealed record App(Guid Id, string Name);

public sealed record Role(Guid Id, Guid AppId, string Name, string Description);

public sealed record User(
    Guid Id,
    string Username,
    string Email,
    string DisplayName,
    bool IsActive,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

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
    DateTimeOffset UpdatedAt);

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
