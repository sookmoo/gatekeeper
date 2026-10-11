using Gatekeeper.Application;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Infrastructure.Postgres;

public static class PostgresStoreExtensions
{
    public static IServiceCollection AddPostgresStore(this IServiceCollection services, string connectionString) => services
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

internal sealed class PostgresReadinessProbe(IDbContextFactory<GatekeeperDbContext> factory) : IReadinessProbe
{
    public async Task<bool> IsReadyAsync(CancellationToken ct = default)
    {
        try
        {
            await using var db = await factory.CreateDbContextAsync(ct);
            return await db.Database.CanConnectAsync(ct);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
