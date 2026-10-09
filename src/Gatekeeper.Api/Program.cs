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

app.UseMiddleware<ErrorMappingMiddleware>();
app.MapOpenApi("/openapi/{documentName}.json");
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).ExcludeFromDescription();
app.MapApi();

app.Run();

public partial class Program;
