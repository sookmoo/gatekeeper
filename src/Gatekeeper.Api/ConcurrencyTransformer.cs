using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Gatekeeper.Api;

/// <summary>
/// Documents optimistic concurrency on applications, roles, users and clients: the required <c>version</c> field, the strong
/// <c>ETag</c> response header on single-resource GET/PUT/PATCH and on create, the optional <c>If-Match</c> request header on
/// PUT/PATCH/DELETE and the 412 answer.
/// </summary>
public sealed class ConcurrencyTransformer : IOpenApiDocumentTransformer
{
    private static readonly string[] Resources = ["/v1/applications/{id}", "/v1/roles/{id}", "/v1/users/{id}", "/v1/clients/{id}"];
    private static readonly string[] Creates = ["/v1/applications", "/v1/applications/{id}/roles", "/v1/users", "/v1/clients"];
    private static readonly string[] Schemas = ["App", "Role", "User", "Client", "ClientCreatedResponse"];

    public const string IfMatchText = "Optional precondition. Send the ETag from an earlier GET, PUT, PATCH or POST of this resource (for example \"3\"), or * for any existing resource. "
        + "When the resource has another version the answer is 412 and nothing changes. Without the header the change is unconditional. "
        + "A header that is not * or a list of entity-tags is 400; a weak tag (W/\"3\") never matches. "
        + "Checks run in this order: 400 (malformed header), 404, 412, then the other checks (body validation 400 and the 409 rules; their order differs a little per resource, see the README). "
        + "A PATCH that changes no value writes nothing and keeps the version.";

    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken ct)
    {
        foreach (var name in Schemas)
        {
            if (document.Components?.Schemas is { } schemas && schemas.TryGetValue(name, out var schema) && schema is OpenApiSchema s)
            {
                s.Required ??= new HashSet<string>();
                s.Required.Add("version");
                // The serializer describes an int64 as integer-or-string with a default; the field is always a JSON number >= 1.
                if (s.Properties is { } props && props.TryGetValue("version", out var version) && version is OpenApiSchema v)
                {
                    v.Type = JsonSchemaType.Integer;
                    v.Format = "int64";
                    v.Pattern = null;
                    v.Default = null;
                    v.Minimum = "1";
                }
            }
        }
        foreach (var path in Resources)
        {
            if (!document.Paths.TryGetValue(path, out var item) || item.Operations is null) continue;
            foreach (var (method, op) in item.Operations)
            {
                if (method == HttpMethod.Get || method == HttpMethod.Put || method == HttpMethod.Patch) AddETag(op, "200");
                if (method == HttpMethod.Put || method == HttpMethod.Patch || method == HttpMethod.Delete)
                {
                    op.Parameters ??= [];
                    op.Parameters.Add(new OpenApiParameter
                    {
                        Name = "If-Match",
                        In = ParameterLocation.Header,
                        Required = false,
                        Description = IfMatchText,
                        Schema = new OpenApiSchema { Type = JsonSchemaType.String },
                    });
                    op.Responses ??= [];
                    op.Responses["412"] = new OpenApiResponse
                    {
                        Description = "Precondition Failed: the resource has another version than the If-Match header says. Nothing was changed.",
                        Content = new Dictionary<string, OpenApiMediaType>
                        {
                            ["application/problem+json"] = new OpenApiMediaType { Schema = new OpenApiSchemaReference("ProblemDetails", document) },
                        },
                    };
                }
            }
        }
        foreach (var path in Creates)
            if (document.Paths.TryGetValue(path, out var item) && item.Operations is not null && item.Operations.TryGetValue(HttpMethod.Post, out var post))
                AddETag(post, "201");
        return Task.CompletedTask;
    }

    private static void AddETag(OpenApiOperation op, string status)
    {
        if (op.Responses is null || !op.Responses.TryGetValue(status, out var response) || response is not OpenApiResponse r) return;
        r.Headers ??= new Dictionary<string, IOpenApiHeader>();
        r.Headers["ETag"] = new OpenApiHeader
        {
            Description = "Strong entity-tag of this version of the resource: the quoted `version` field, for example \"3\". Use it in If-Match.",
            Schema = new OpenApiSchema { Type = JsonSchemaType.String },
        };
    }
}
