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

var refreshDays = builder.Configuration.GetValue("Auth:RefreshTokenDays", 30);
var graceSeconds = builder.Configuration.GetValue("Auth:RefreshReuseGraceSeconds", 10);
if (graceSeconds is < 0 or > 60) return Fail("Auth:RefreshReuseGraceSeconds must be between 0 and 60.");
if (refreshDays is < 1 or > 90) return Fail("Auth:RefreshTokenDays must be between 1 and 90.");
// Slice 7d: bounds on the audit rows a self-service token can cause.
var meWrites = builder.Configuration.GetValue("Audit:MeWritesPerMinute", 30);
var failureRows = builder.Configuration.GetValue("Audit:FailureRowsPerMinute", 5);
if (meWrites is < 1 or > 10_000) return Fail("Audit:MeWritesPerMinute must be between 1 and 10000.");
if (failureRows is < 1 or > 1_000) return Fail("Audit:FailureRowsPerMinute must be between 1 and 1000.");
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
    .AddSingleton(new RefreshOptions { RefreshLifetime = TimeSpan.FromDays(refreshDays), ReuseGrace = TimeSpan.FromSeconds(graceSeconds) })
    .AddSingleton<SessionService>()
    .AddSingleton<Introspector>()
    .AddSingleton<ClientService>()
    .AddSingleton<ClientAuthService>()
    .AddKeyedSingleton<LoginThrottle>("client", (_, _) => new LoginThrottle())
    .AddKeyedSingleton<LoginThrottle>("refresh", (_, _) => new LoginThrottle())
    // Dead (revoked, expired) sessions whose token is replayed: a few failures per session per window, then 429.
    .AddKeyedSingleton<LoginThrottle>("refreshSession", (_, _) => new LoginThrottle(maxPerAddress: AuthEndpoints.SessionFailuresAllowed))
    // Own password change (slice 6g): failed attempts per user (all addresses) and per client address, then 429 without hashing.
    .AddKeyedSingleton<LoginThrottle>("passwordUser", (_, _) => new LoginThrottle(maxPerAddress: Endpoints.PasswordFailuresPerUser))
    .AddKeyedSingleton<LoginThrottle>("passwordAddress", (_, _) => new LoginThrottle(maxPerAddress: Endpoints.PasswordFailuresPerAddress))
    .AddSingleton<AuditService>()
    .AddSingleton(new AuditCoalescer(freePerWindow: failureRows))
    .AddHostedService<AuditSummaryFlusher>()
    .AddKeyedSingleton<LoginThrottle>(MeWriteLimitMiddleware.KeyName, (_, _) => new LoginThrottle(maxPerAddress: meWrites, window: TimeSpan.FromMinutes(1)))
    .AddSingleton<AuditRecorder>()
    .AddSingleton<LoginThrottle>()
    .AddProblemDetails()
    .ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new UserKindConverter()))
    .AddOpenApi(o =>
    {
        o.AddDocumentTransformer<BearerSecurityTransformer>();
        o.AddDocumentTransformer<ConcurrencyTransformer>();
        // The kind has its own converter, so describe it here: exactly one of three words.
        o.AddSchemaTransformer((schema, context, _) =>
        {
            if ((Nullable.GetUnderlyingType(context.JsonTypeInfo.Type) ?? context.JsonTypeInfo.Type) == typeof(Gatekeeper.Domain.UserKind))
            {
                schema.Type = Microsoft.OpenApi.JsonSchemaType.String;
                schema.Enum = ["person", "test", "shared"];
            }
            return Task.CompletedTask;
        });
    });

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
    IReadOnlyDictionary<ECDsa, DateTimeOffset> retiredAt = new Dictionary<ECDsa, DateTimeOffset>();
    var retiredFile = builder.Configuration["Auth:RetiredKeysPemFile"];
    var retiredPem = builder.Configuration["Auth:RetiredKeysPem"];
    try
    {
        if (!string.IsNullOrWhiteSpace(retiredFile)) retiredPem = File.ReadAllText(retiredFile);
        if (!string.IsNullOrWhiteSpace(retiredPem)) retired = TokenService.LoadRetiredKeys(retiredPem, out retiredAt);
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
        }, retired, retiredAt);
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
                // Only liveness of the subject is decided here (unknown, disabled or expired user, ended session: 401). What the
                // subject may do (admin role, self-service) is decided by the policies, so a valid token without the admin role is 403.
                if (ctx.Principal is null || AdminAccessCheck.Subject(ctx.Principal) is not var (userId, sessionId))
                    ctx.Fail("Invalid token.");
                else if (await access.StateAsync(userId, sessionId, AdminAccessCheck.AuthTime(ctx.Principal), ctx.HttpContext.RequestAborted) is null)
                    ctx.Fail("The user is no longer active.");
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
            IssuerSigningKeyResolver = (_, _, _, _) => tokens.VerificationKeys, // evaluated per request: retired keys age out
            LifetimeValidator = tokens.LifetimeValidator(TimeSpan.FromSeconds(30)),
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidTypes = [TokenService.TokenType],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "sub",
            RoleClaimType = TokenService.RolesClaim,
        };
    });
    builder.Services.AddAuthorizationBuilder()
        // Management API: the admin role claim AND a store check (AccessHandler). Self-service: any usable person or test user.
        .AddPolicy(Endpoints.AdminPolicy, p => p.RequireAuthenticatedUser().RequireRole(Reserved.AdminRole).AddRequirements(new AdminRequirement()))
        .AddPolicy(Endpoints.SelfPolicy, p => p.RequireAuthenticatedUser().RequireClaim("aud", Reserved.AdminApp).AddRequirements(new SelfRequirement()))
        // The readiness probe deliberately trusts the signed admin role claim alone (it must answer while the store is down).
        .AddPolicy(Endpoints.ReadyPolicy, p => p.RequireAuthenticatedUser().RequireRole(Reserved.AdminRole))
        // Fail closed: an endpoint added without a policy needs an administrator. Public routes say AllowAnonymous explicitly.
        .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser().RequireRole(Reserved.AdminRole).AddRequirements(new AdminRequirement()).Build());
    builder.Services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, AccessHandler>();
}

var trustedProxies = new List<System.Net.IPAddress>();
var proxies = (builder.Configuration["Auth:TrustedProxies"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
if (proxies.Length > 0)
{
    var parsed = new List<System.Net.IPAddress>();
    foreach (var p in proxies)
    {
        // IPAddress.TryParse also accepts shorthand such as "10" (0.0.0.10): insist on a full address.
        if (!(p.Contains('.') || p.Contains(':')) || !System.Net.IPAddress.TryParse(p, out var ip)) return Fail($"Auth:TrustedProxies contains an invalid address '{p}'.");
        parsed.Add(ip);
    }
    trustedProxies.AddRange(parsed.Select(ip => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip));
    builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor;
        o.ForwardLimit = 1;
        o.KnownProxies.Clear();
        o.KnownIPNetworks.Clear();
        foreach (var ip in parsed) o.KnownProxies.Add(ip);
    });
}

builder.Services.AddSingleton(new ForwardedHeaderWarning(trustedProxies));
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

// Before the forwarded-headers middleware: it sees the real peer and the header as sent.
app.Use(async (http, next) =>
{
    if (http.Request.Headers.ContainsKey("X-Forwarded-For")
        && http.RequestServices.GetRequiredService<ForwardedHeaderWarning>().Check(http.Connection.RemoteIpAddress, hasForwardedFor: true) is { } peer)
        app.Logger.LogWarning("A request from {Peer} carried X-Forwarded-For, but that address is not in Auth:TrustedProxies, so the header is ignored. If that address is your reverse proxy, add it to Auth__TrustedProxies (until then all callers behind it share one throttle bucket); otherwise a client is sending X-Forwarded-For directly and the header is correctly ignored.", peer);
    await next();
});
if (proxies.Length > 0) app.UseForwardedHeaders(); // before anything that reads the client address
// Registered in every environment so unhandled errors never leak stack traces or headers.
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseMiddleware<ErrorMappingMiddleware>();
// Nothing matched: a plain 404 for everyone (the fallback policy below is for endpoints, and must not turn unknown URLs into 401/403).
app.Use(async (http, next) =>
{
    var endpoint = http.GetEndpoint();
    if (endpoint is null) { http.Response.StatusCode = StatusCodes.Status404NotFound; return; }
    // The router's "405 HTTP Method Not Supported" endpoint has no policy: run it as it is (it answers 405 with an Allow header) instead of
    // letting the fallback policy answer 401/403. Real endpoints still go through authorization.
    if (endpoint.DisplayName?.StartsWith("405", StringComparison.Ordinal) == true && endpoint.RequestDelegate is { } handler) { await handler(http); return; }
    await next();
});
app.UseAuthentication();
app.UseMiddleware<ForbiddenAuditMiddleware>();
app.UseAuthorization();
app.UseMiddleware<AuditMiddleware>();
app.UseMiddleware<MeWriteLimitMiddleware>(); // inside the audit middleware: a refused call sets SkipKey and writes no row
app.MapOpenApi("/openapi/{documentName}.json").AllowAnonymous();
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).ExcludeFromDescription().AllowAnonymous();
// It queries the store and reveals its state, so it needs an admin token (role claim only, see ReadyPolicy); the answer is still cached briefly.
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
    .RequireAuthorization(Endpoints.ReadyPolicy)
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
