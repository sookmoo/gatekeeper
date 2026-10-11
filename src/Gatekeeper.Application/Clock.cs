namespace Gatekeeper.Application;

public static class Clock
{
    /// <summary>UTC now truncated to microseconds, the precision of PostgreSQL timestamptz.</summary>
    public static DateTimeOffset UtcNowMicros()
    {
        var now = DateTimeOffset.UtcNow;
        return new DateTimeOffset(now.Ticks - now.Ticks % 10, TimeSpan.Zero);
    }
}
