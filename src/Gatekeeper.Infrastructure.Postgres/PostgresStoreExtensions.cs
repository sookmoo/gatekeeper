using Gatekeeper.Application;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeeper.Infrastructure.Postgres;

public static class PostgresStoreExtensions
{
    public static IServiceCollection AddPostgresStore(this IServiceCollection services, string connectionString) => services
        .AddLogging()
        .AddDbContextFactory<GatekeeperDbContext>(o => o.UseNpgsql(connectionString), ServiceLifetime.Singleton)
        .AddSingleton<IAppRepository, PostgresAppRepository>()
        .AddSingleton<IRoleRepository, PostgresRoleRepository>()
        .AddSingleton<IUserRepository, PostgresUserRepository>()
        .AddSingleton<IReadinessProbe, PostgresReadinessProbe>();

    /// <summary>Applies pending EF migrations. Run as a one-off admin step, never from the serving process.</summary>
    public static async Task MigrateAsync(IServiceProvider services, CancellationToken ct = default)
    {
        await using var db = await services.GetRequiredService<IDbContextFactory<GatekeeperDbContext>>().CreateDbContextAsync(ct);
        await db.Database.MigrateAsync(ct);
    }
}

internal sealed class PostgresReadinessProbe(
    IDbContextFactory<GatekeeperDbContext> factory, ILogger<PostgresReadinessProbe> logger) : IReadinessProbe
{
    public async Task<bool> IsReadyAsync(CancellationToken ct = default)
    {
        try
        {
            await using var db = await factory.CreateDbContextAsync(ct);
            if (!await db.Database.CanConnectAsync(ct)) return false;

            // Reachable but not migrated: every request would fail, so do not report ready.
            var pending = await db.Database.GetPendingMigrationsAsync(ct);
            if (pending.Any())
            {
                logger.LogWarning("Database has pending migrations; run the migrate command.");
                return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Npgsql messages do not contain the password, so the message is safe to log.
            logger.LogWarning("Readiness check failed: {Type} {SqlState} {Message}",
                ex.GetType().Name, (ex as PostgresException)?.SqlState, ex.Message);
            return false;
        }
    }
}
