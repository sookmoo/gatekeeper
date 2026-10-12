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

builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.Limits.MaxRequestBodySize = 64 * 1024; // the largest legitimate body is a few hundred bytes
});
var ephemeralKey = false;
var provider = builder.Configuration["Store:Provider"] ?? "InMemory";
// A container or proxy deployment that forgot Store__Provider must not silently run an empty in-memory store.
if (builder.Configuration["Store:Provider"] is null && builder.Configuration.GetValue<bool>("Gatekeeper:AllowNonLoopback"))
    return Fail("Store:Provider is not set (use the Store__Provider environment variable).");
if (builder.Configuration.GetValue<bool>("Auth:SeedDevAdmin") && builder.Configuration.GetValue<bool>("Gatekeeper:AllowNonLoopback"))
    return Fail("Auth:SeedDevAdmin must not be combined with Gatekeeper:AllowNonLoopback.");
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
    .AddSingleton<HashLimiter>()
    .AddSingleton<AdminGuard>()
    .AddSingleton<AdminAccessCheck>()
    .AddMemoryCache()
    .AddSingleton<AuthService>()
    .AddSingleton<ClientService>()
    .AddSingleton<ClientAuthService>()
    .AddKeyedSingleton<LoginThrottle>("client", (_, _) => new LoginThrottle())
    .AddSingleton<AuditService>()
    .AddSingleton<AuditRecorder>()
    .AddSingleton<LoginThrottle>()
    .AddProblemDetails()
    .AddOpenApi(o => o.AddDocumentTransformer<BearerSecurityTransformer>());

if (!migrateOnly && !bootstrap)
{
    var pem = builder.Configuration["Auth:SigningKeyPem"];
    var pemFile = builder.Configuration["Auth:SigningKeyPemFile"];
    if (!string.IsNullOrWhiteSpace(pemFile))
    {
        try
        {
            pem = File.ReadAllText(pemFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Fail($"Cannot read Auth:SigningKeyPemFile: {ex.Message}");
        }
    }
    ECDsa signingKey;
    try
    {
        signingKey = !string.IsNullOrWhiteSpace(pem) ? TokenService.LoadKey(pem)
            : provider == "InMemory" ? TokenService.NewKey()
            : throw new InvalidOperationException("Auth:SigningKeyPem is not set (use a secret file with Auth__SigningKeyPemFile, or Auth__SigningKeyPem).");
        ephemeralKey = string.IsNullOrWhiteSpace(pem);
    }
    catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException)
    {
        return Fail($"Invalid signing key configuration: {ex.Message}");
    }

    // Retired keys stay published (and accepted) until the tokens they signed have expired; see README "Key rotation".
    var retired = new List<ECDsa>();
    var retiredFile = builder.Configuration["Auth:RetiredKeysPemFile"];
    var retiredPem = builder.Configuration["Auth:RetiredKeysPem"];
    try
    {
        if (!string.IsNullOrWhiteSpace(retiredFile)) retiredPem = File.ReadAllText(retiredFile);
        if (!string.IsNullOrWhiteSpace(retiredPem)) retired = TokenService.LoadRetiredKeys(retiredPem);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
    {
        return Fail($"Invalid retired keys configuration: {ex.Message}");
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
        }, retired);
    }
    catch (ArgumentException ex)
    {
        return Fail($"Invalid signing key configuration: {ex.Message}");
    }

    builder.Services.AddSingleton(tokenService);
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
    // The management API accepts only our own access tokens issued for the admin application.
    builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).Configure<TokenService, AdminAccessCheck>((o, tokens, access) =>
    {
        o.MapInboundClaims = false;
        // A valid signature is not enough: the user must still be an active administrator right now.
        o.Events = new JwtBearerEvents
        {
            // Only the management API and the readiness probe use tokens: a stray Authorization header must not make /health or the JWKS touch the store.
            OnMessageReceived = ctx =>
            {
                var path = ctx.Request.Path;
                if ((!path.StartsWithSegments("/v1") && !path.StartsWithSegments("/health/ready")) || path.StartsWithSegments("/v1/auth")) ctx.NoResult();
                return Task.CompletedTask;
            },
            OnTokenValidated = async ctx =>
            {
                // The readiness probe must keep answering when the store is down or unmigrated, so it relies on the
                // signed admin token alone; it only reveals whether the service is ready.
                if (ctx.Request.Path.StartsWithSegments("/health/ready")) return;
                if (!Guid.TryParse(ctx.Principal?.FindFirst("sub")?.Value, out var userId)
                    || !await access.IsAdminAsync(userId, ctx.HttpContext.RequestAborted))
                    ctx.Fail("The user is no longer an active administrator.");
            },
        };
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
            IssuerSigningKeys = tokens.VerificationKeys,
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

var proxies = (builder.Configuration["Auth:TrustedProxies"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
if (proxies.Length > 0)
{
    var parsed = new List<System.Net.IPAddress>();
    foreach (var p in proxies)
    {
        if (!System.Net.IPAddress.TryParse(p, out var ip)) return Fail($"Auth:TrustedProxies contains an invalid address '{p}'.");
        parsed.Add(ip);
    }
    builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor;
        o.ForwardLimit = 1;
        o.KnownProxies.Clear();
        o.KnownIPNetworks.Clear();
        foreach (var ip in parsed) o.KnownProxies.Add(ip);
    });
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

if (proxies.Length > 0) app.UseForwardedHeaders(); // before anything that reads the client address
// Registered in every environment so unhandled errors never leak stack traces or headers.
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseMiddleware<ErrorMappingMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<AuditMiddleware>();
app.MapOpenApi("/openapi/{documentName}.json");
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).ExcludeFromDescription();
// It queries the store and reveals its state, so it needs an admin token; the answer is still cached briefly.
var readyLock = new object();
var readyAt = DateTimeOffset.MinValue;
var readyResult = false;
app.MapGet("/health/ready", async (IReadinessProbe probe, CancellationToken ct) =>
    {
        bool cached;
        lock (readyLock) cached = DateTimeOffset.UtcNow - readyAt < TimeSpan.FromSeconds(2);
        var ready = cached ? readyResult : await probe.IsReadyAsync(ct);
        if (!cached) lock (readyLock) (readyAt, readyResult) = (DateTimeOffset.UtcNow, ready);
        return ready ? Results.Ok(new { status = "ready" }) : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    })
    .RequireAuthorization(Endpoints.AdminPolicy)
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
