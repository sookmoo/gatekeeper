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

/// <summary>An If-Match precondition did not hold: the row's version is not the one the caller saw (HTTP 412). Nothing was changed.</summary>
public sealed class PreconditionFailedException() : GatekeeperException("The resource was changed by someone else. Fetch it again and retry.");

public sealed class ConflictException(string message) : GatekeeperException(message);

/// <summary>Too much password hashing is queued; the caller may retry shortly (HTTP 503).</summary>
public sealed class BusyException() : GatekeeperException("The server is busy. Try again shortly.");
