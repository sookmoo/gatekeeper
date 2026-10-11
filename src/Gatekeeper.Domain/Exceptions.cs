namespace Gatekeeper.Domain;

public class GatekeeperException(string message) : Exception(message);

public sealed class ValidationException(IReadOnlyDictionary<string, string> errors)
    : GatekeeperException("Validation failed.")
{
    public IReadOnlyDictionary<string, string> Errors { get; } = errors;
}

public sealed class NotFoundException(string message) : GatekeeperException(message);

/// <summary>The backing store cannot be reached or is overloaded; the caller may retry later.</summary>
public sealed class StoreUnavailableException(string message, Exception? inner = null) : GatekeeperException(message)
{
    public Exception? Cause { get; } = inner;
}

public sealed class ConflictException(string message) : GatekeeperException(message);
