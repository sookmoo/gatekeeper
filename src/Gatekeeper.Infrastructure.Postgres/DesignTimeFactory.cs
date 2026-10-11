using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Gatekeeper.Infrastructure.Postgres;

/// <summary>Used only by `dotnet ef`. Generating migrations needs no live database.</summary>
public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<GatekeeperDbContext>
{
    public GatekeeperDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<GatekeeperDbContext>()
            .UseNpgsql(Environment.GetEnvironmentVariable("GATEKEEPER_EF_CONNECTION")
                       ?? "Host=localhost;Database=gatekeeper_design")
            .Options);
}
