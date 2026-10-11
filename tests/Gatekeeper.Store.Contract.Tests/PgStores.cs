using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

internal static class PgStores
{
    /// <summary>Migrates as the owner, then returns a provider that uses the data-only app role.</summary>
    public static ServiceProvider OpenAsAppRole(PgTestDatabase db)
    {
        using (var migrator = new ServiceCollection().AddPostgresStore(db.MigratorConnection).BuildServiceProvider())
            PostgresStoreExtensions.MigrateAsync(migrator).GetAwaiter().GetResult();
        db.GrantAppAccess();
        return new ServiceCollection().AddPostgresStore(db.AppConnection).BuildServiceProvider();
    }
}
