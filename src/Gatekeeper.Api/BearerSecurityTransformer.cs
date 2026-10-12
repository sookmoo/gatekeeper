using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Gatekeeper.Api;

/// <summary>Declares the JWT bearer scheme and requires it on every operation except login (which is public).</summary>
public sealed class BearerSecurityTransformer : IOpenApiDocumentTransformer
{
    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken ct)
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Access token from POST /v1/auth/login for an administrator.",
        };
        foreach (var (path, item) in document.Paths)
        {
            if (path == "/v1/auth/login" || item.Operations is null) continue;
            foreach (var op in item.Operations.Values)
                op.Security = [new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("bearer", document)] = [] }];
        }
        return Task.CompletedTask;
    }
}
