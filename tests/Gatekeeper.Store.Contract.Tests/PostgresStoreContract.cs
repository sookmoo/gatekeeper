using Gatekeeper.Application;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>
/// Runs the contract against a real Postgres, using the data-only app role (no DDL rights).
/// Set GATEKEEPER_TEST_PG to an admin connection string (see scripts/test-pg.sh); otherwise the
/// tests are reported as skipped. Each test gets its own freshly migrated database.
/// </summary>
public class PostgresStoreContract : StoreContract
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _databases = [];

    protected override (IAppRepository, IRoleRepository, IUserRepository) CreateStore()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres contract tests skipped.");
        _databases.Add(db!);

        var provider = PgStores.OpenAsAppRole(db!);
        _providers.Add(provider);
        Credentials = provider.GetRequiredService<ICredentialRepository>();
        return (provider.GetRequiredService<IAppRepository>(),
                provider.GetRequiredService<IRoleRepository>(),
                provider.GetRequiredService<IUserRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _databases) d.Dispose();
        base.Dispose();
    }
}
