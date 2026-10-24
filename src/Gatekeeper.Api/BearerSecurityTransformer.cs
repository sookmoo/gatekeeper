using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Gatekeeper.Api;

/// <summary>Declares the JWT bearer scheme and requires it on every operation except the public ones.</summary>
public sealed class BearerSecurityTransformer : IOpenApiDocumentTransformer
{
    // Routes that must work without a token (everything else needs an admin bearer token).
    private static readonly HashSet<string> Anonymous = ["/v1/auth/login", "/v1/auth/client-token", "/v1/auth/refresh", "/v1/auth/logout", "/v1/auth/introspect", "/.well-known/jwks.json"];

    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken ct)
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Access token from POST /v1/auth/login for the gatekeeper application. The management routes need the administrator role (policy admin); the /v1/me routes accept any usable person or test user, with or without roles (policy self).",
        };
        document.Components.SecuritySchemes["clientBasic"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "basic",
            Description = "A service identity's client id and secret (used by POST /v1/auth/introspect).",
        };
        foreach (var (path, item) in document.Paths)
        {
            if (path == "/v1/auth/introspect" && item.Operations is not null)
            {
                foreach (var op in item.Operations.Values)
                {
                    op.Security = [new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("clientBasic", document)] = [] }];
                    // The endpoint reads the body itself after authenticating, so describe it here.
                    op.RequestBody = new OpenApiRequestBody
                    {
                        Required = true,
                        Content = new Dictionary<string, OpenApiMediaType>
                        {
                            ["application/json"] = new OpenApiMediaType
                            {
                                Schema = new OpenApiSchema
                                {
                                    Type = JsonSchemaType.Object,
                                    Properties = new Dictionary<string, IOpenApiSchema> { ["token"] = new OpenApiSchema { Type = JsonSchemaType.String } },
                                },
                            },
                        },
                    };
                }
                continue;
            }
            if (Anonymous.Contains(path) || item.Operations is null) continue;
            foreach (var op in item.Operations.Values)
            {
                op.Security = [new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("bearer", document)] = [] }];
                // Which authorization policy guards the operation: self (any person or test user, own data only) or admin.
                op.Extensions ??= new Dictionary<string, IOpenApiExtension>();
                op.Extensions["x-gatekeeper-access"] = new JsonNodeExtension(System.Text.Json.Nodes.JsonValue.Create((path == "/v1/me" || path.StartsWith("/v1/me/", StringComparison.Ordinal)) ? "self" : "admin"));
            }
        }
        // Superseded by DELETE /v1/users/{id}/sessions/{sessionId} (slice 6b); kept for existing callers.
        if (document.Paths.TryGetValue("/v1/sessions/{id}", out var old) && old.Operations is not null
            && old.Operations.TryGetValue(HttpMethod.Delete, out var oldDelete))
            oldDelete.Deprecated = true;
        return Task.CompletedTask;
    }
}
