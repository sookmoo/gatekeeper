namespace Gatekeeper.Domain;

public class GatekeeperException(string message) : Exception(message);

public sealed class ValidationException(IReadOnlyDictionary<string, string> errors)
    : GatekeeperException("Validation failed.")
{
    public IReadOnlyDictionary<string, string> Errors { get; } = errors;
}

public sealed class NotFoundException(string message) : GatekeeperException(message);

public sealed class ConflictException(string message) : GatekeeperException(message);
