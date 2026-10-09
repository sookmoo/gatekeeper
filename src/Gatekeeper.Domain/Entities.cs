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
