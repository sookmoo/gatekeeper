using Gatekeeper.Api;
using Gatekeeper.Application;
using Gatekeeper.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddInMemoryStore()
    .AddSingleton<AppService>()
    .AddSingleton<RoleService>()
    .AddSingleton<UserService>()
    .AddProblemDetails()
    .AddOpenApi();

var app = builder.Build();

// Registered in every environment so unhandled errors never leak stack traces or headers.
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseMiddleware<ErrorMappingMiddleware>();
app.MapOpenApi("/openapi/{documentName}.json");
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).ExcludeFromDescription();
app.MapApi();

await app.StartAsync();
LoopbackGuard.EnsureLoopbackOnly(app);
await app.WaitForShutdownAsync();

public partial class Program;
