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
    long Version = 1,
    [property: System.Text.Json.Serialization.JsonIgnore] DateTimeOffset? SessionsValidAfter = null) : IVersioned
{
    /// <summary>
    /// Whether a session (or a token with no session) that was authenticated at <paramref name="authenticatedAt"/> still counts: only a
    /// sign-in that started strictly after the user's cut-off does. Null cut-off: every sign-in counts.
    /// </summary>
    public bool CountsAfterCutOff(DateTimeOffset authenticatedAt) => SessionsValidAfter is not { } cut || authenticatedAt > cut;

    /// <summary>
    /// The same check for a token without a session, which only carries whole seconds (<c>auth_time</c>, or <c>iat</c> for older tokens).
    /// Conservative: a sign-in in the same second as the cut-off does not count (the user signs in again). A token with neither claim
    /// (null) does not count once a cut-off exists.
    /// </summary>
    public bool TokenCountsAfterCutOff(long? authTimeSeconds) => TokenCountsAfterCutOff(SessionsValidAfter, authTimeSeconds);

    public static bool TokenCountsAfterCutOff(DateTimeOffset? cutOff, long? authTimeSeconds) =>
        cutOff is not { } cut || (authTimeSeconds is { } t && t > cut.ToUnixTimeSeconds());

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
    DateTimeOffset? RevokedAt,
    [property: System.Text.Json.Serialization.JsonIgnore] DateTimeOffset? AuthenticatedAt = null)
{
    /// <summary>
    /// When the sign-in that started the session began (taken before the password hash was read; a refresh keeps it). The session counts only
    /// while this is after the user's <see cref="User.SessionsValidAfter"/>. Null on a value built by older code: <see cref="CreatedAt"/> then;
    /// the stores always return it set.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public DateTimeOffset Stamp => AuthenticatedAt ?? CreatedAt;

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
}
