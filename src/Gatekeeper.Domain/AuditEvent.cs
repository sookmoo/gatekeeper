namespace Gatekeeper.Domain;

/// <summary>
/// One immutable record of something that happened. Actor is a user id, a client id, "system" or "anonymous";
/// Target identifies what was acted on (never a secret). Detail is short free text (never a password or token).
/// </summary>
public sealed record AuditEvent(
    Guid Id, DateTimeOffset At, string Actor, string Action, string? Target, string Outcome, string? Detail, string? Address)
{
    public const string Success = "success";
    public const string Failure = "failure";
    public const int MaxField = 200;
}
