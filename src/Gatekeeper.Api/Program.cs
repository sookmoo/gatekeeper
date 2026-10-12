using System.Security.Cryptography;
using Gatekeeper.Api;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Infrastructure.Postgres;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

// `Gatekeeper.Api migrate` is a one-off admin step: apply database migrations, then exit.
// It uses ConnectionStrings:GatekeeperMigrations (an owner role); serving uses ConnectionStrings:Gatekeeper
// (a role with data access only), so the running service never holds DDL rights.
if (args.Length > 1 && args[0] == "migrate") return Fail("'migrate' takes no arguments.");
// `Gatekeeper.Api healthcheck` is the container HEALTHCHECK (the runtime image has no shell or curl).
if (args is ["healthcheck"]) return await HealthCheck.RunAsync();
// `Gatekeeper.Api bootstrap-admin <username> <email>` creates the first administrator (password from stdin or
// GATEKEEPER_BOOTSTRAP_PASSWORD). It runs once, like migrate, and uses the normal (data-only) connection.
var bootstrap = args is ["bootstrap-admin", ..];
if (bootstrap && args.Length != 3) return Fail("usage: bootstrap-admin <username> <email>");
var migrateOnly = args is ["migrate"];
var builder = WebApplication.CreateBuilder(migrateOnly || bootstrap ? [] : args);
if (migrateOnly)
{
    // EF logs the expected "history table does not exist yet" probe on an empty database as an error.
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.None);
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Connection", LogLevel.None);
}

var ephemeralKey = false;
var provider = builder.Configuration["Store:Provider"] ?? "InMemory";
switch (provider)
{
    case "InMemory":
        if (migrateOnly) return Fail("Nothing to migrate: Store:Provider is InMemory.");
        if (bootstrap) return Fail("Nothing to bootstrap: Store:Provider is InMemory (data would be lost on exit).");
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
    .AddSingleton<AuthService>()
    .AddSingleton<LoginThrottle>()
    .AddProblemDetails()
    .AddOpenApi();

if (!migrateOnly && !bootstrap)
{
    var pem = builder.Configuration["Auth:SigningKeyPem"];
    ECDsa signingKey;
    try
    {
        signingKey = !string.IsNullOrWhiteSpace(pem) ? TokenService.LoadKey(pem)
            : provider == "InMemory" ? TokenService.NewKey()
            : throw new InvalidOperationException("Auth:SigningKeyPem is not set (use the Auth__SigningKeyPem environment variable).");
        ephemeralKey = string.IsNullOrWhiteSpace(pem);
    }
    catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException)
    {
        return Fail($"Invalid signing key configuration: {ex.Message}");
    }

    var minutes = builder.Configuration.GetValue("Auth:AccessTokenMinutes", 15);
    if (minutes is < 1 or > 60) return Fail("Auth:AccessTokenMinutes must be between 1 and 60.");
    TokenService tokenService;
    try
    {
        tokenService = new TokenService(signingKey, new AuthOptions
        {
            Issuer = builder.Configuration["Auth:Issuer"] ?? "gatekeeper",
            AccessTokenLifetime = TimeSpan.FromMinutes(minutes),
        });
    }
    catch (ArgumentException ex)
    {
        return Fail($"Invalid signing key configuration: {ex.Message}");
    }

    builder.Services.AddSingleton(tokenService);
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
    // The management API accepts only our own access tokens issued for the admin application.
    builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).Configure<TokenService>((o, tokens) =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = tokens.Issuer,
            ValidateAudience = true,
            ValidAudience = Reserved.AdminApp,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = tokens.PublicKey,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidTypes = [TokenService.TokenType],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "sub",
            RoleClaimType = TokenService.RolesClaim,
        };
    });
    builder.Services.AddAuthorizationBuilder()
        .AddPolicy(Endpoints.AdminPolicy, p => p.RequireAuthenticatedUser().RequireRole(Reserved.AdminRole));
}

var app = builder.Build();
if (ephemeralKey)
    app.Logger.LogWarning("Auth:SigningKeyPem is not set: using a temporary signing key. Tokens stop working on restart.");

if (bootstrap)
    return await Bootstrap.RunAsync(app.Services, args[1], args[2]);

// Local development only: the in-memory store starts empty, so nobody could log in. Opt in explicitly.
if (builder.Configuration.GetValue<bool>("Auth:SeedDevAdmin"))
{
    if (provider != "InMemory") return Fail("Auth:SeedDevAdmin is only allowed with Store:Provider=InMemory.");
    var devPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
    await Bootstrap.CreateAdminAsync(app.Services, "admin", "admin@localhost.example", devPassword);
    app.Logger.LogWarning("Development administrator created. Username: admin  Password: {Password}  (in-memory data, lost on exit)", devPassword);
}

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
app.UseAuthentication();
app.UseAuthorization();
app.MapOpenApi("/openapi/{documentName}.json");
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).ExcludeFromDescription();
app.MapGet("/health/ready", async (IReadinessProbe probe, CancellationToken ct) =>
        await probe.IsReadyAsync(ct) ? Results.Ok(new { status = "ready" }) : Results.StatusCode(StatusCodes.Status503ServiceUnavailable))
    .ExcludeFromDescription();
app.MapApi();
app.MapAuth();

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
