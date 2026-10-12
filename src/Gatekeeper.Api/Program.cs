using Gatekeeper.Api;
using Gatekeeper.Application;
using Gatekeeper.Infrastructure;
using Gatekeeper.Infrastructure.Postgres;

// `Gatekeeper.Api migrate` is a one-off admin step: apply database migrations, then exit.
// It uses ConnectionStrings:GatekeeperMigrations (an owner role); serving uses ConnectionStrings:Gatekeeper
// (a role with data access only), so the running service never holds DDL rights.
if (args.Length > 1 && args[0] == "migrate") return Fail("'migrate' takes no arguments.");
// `Gatekeeper.Api healthcheck` is the container HEALTHCHECK (the runtime image has no shell or curl).
if (args is ["healthcheck"]) return await HealthCheck.RunAsync();
var migrateOnly = args is ["migrate"];
var builder = WebApplication.CreateBuilder(migrateOnly ? [] : args);
if (migrateOnly)
{
    // EF logs the expected "history table does not exist yet" probe on an empty database as an error.
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.None);
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Connection", LogLevel.None);
}

var provider = builder.Configuration["Store:Provider"] ?? "InMemory";
switch (provider)
{
    case "InMemory":
        if (migrateOnly) return Fail("Nothing to migrate: Store:Provider is InMemory.");
        builder.Services.AddInMemoryStore();
        break;
    case "Postgres":
        var setting = migrateOnly ? "GatekeeperMigrations" : "Gatekeeper";
        var connection = builder.Configuration.GetConnectionString(setting);
        if (string.IsNullOrWhiteSpace(connection))
            return Fail($"Store:Provider is Postgres but ConnectionStrings:{setting} is not set " +
                        $"(use the ConnectionStrings__{setting} environment variable).");
        builder.Services.AddPostgresStore(connection);
        break;
    default:
        return Fail($"Unknown Store:Provider '{provider}'. Use InMemory or Postgres.");
}

builder.Services
    .AddSingleton<AppService>()
    .AddSingleton<RoleService>()
    .AddSingleton<UserService>()
    .AddSingleton<IPasswordHasher, Argon2PasswordHasher>()
    .AddSingleton<CredentialService>()
    .AddProblemDetails()
    .AddOpenApi();

var app = builder.Build();

if (migrateOnly)
{
    try
    {
        await PostgresStoreExtensions.MigrateAsync(app.Services);
        Console.WriteLine("Migrations applied.");
        return 0;
    }
    catch (Exception ex)
    {
        // Npgsql messages do not include the password.
        return Fail($"Migration failed: {ex.GetType().Name}: {ex.Message}");
    }
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
return 0;

static int Fail(string message)
{
    Console.Error.WriteLine($"error: {message}");
    return 1;
}

public partial class Program;
