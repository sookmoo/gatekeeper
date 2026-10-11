using Gatekeeper.Api;
using Gatekeeper.Application;
using Gatekeeper.Infrastructure;
using Gatekeeper.Infrastructure.Postgres;

// `Gatekeeper.Api migrate` is a one-off admin step: apply database migrations, then exit.
var migrateOnly = args is ["migrate"];
var builder = WebApplication.CreateBuilder(migrateOnly ? [] : args);

var provider = builder.Configuration["Store:Provider"] ?? "InMemory";
switch (provider)
{
    case "InMemory":
        if (migrateOnly) throw new InvalidOperationException("Nothing to migrate: Store:Provider is InMemory.");
        builder.Services.AddInMemoryStore();
        break;
    case "Postgres":
        var connection = builder.Configuration.GetConnectionString("Gatekeeper");
        if (string.IsNullOrWhiteSpace(connection))
            throw new InvalidOperationException(
                "Store:Provider is Postgres but ConnectionStrings:Gatekeeper is not set " +
                "(use the ConnectionStrings__Gatekeeper environment variable).");
        builder.Services.AddPostgresStore(connection);
        break;
    default:
        throw new InvalidOperationException($"Unknown Store:Provider '{provider}'. Use InMemory or Postgres.");
}

builder.Services
    .AddSingleton<AppService>()
    .AddSingleton<RoleService>()
    .AddSingleton<UserService>()
    .AddProblemDetails()
    .AddOpenApi();

var app = builder.Build();

if (migrateOnly)
{
    await PostgresStoreExtensions.MigrateAsync(app.Services);
    Console.WriteLine("Migrations applied.");
    return;
}

// Registered in every environment so unhandled errors never leak stack traces or headers.
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseMiddleware<ErrorMappingMiddleware>();
app.MapOpenApi("/openapi/{documentName}.json");
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).ExcludeFromDescription();
app.MapGet("/health/ready", async (IReadinessProbe probe, CancellationToken ct) =>
        await probe.IsReadyAsync(ct) ? Results.Ok(new { status = "ready" }) : Results.StatusCode(StatusCodes.Status503ServiceUnavailable))
    .ExcludeFromDescription();
app.MapApi();

await app.StartAsync();
LoopbackGuard.EnsureLoopbackOnly(app);
await app.WaitForShutdownAsync();

public partial class Program;
