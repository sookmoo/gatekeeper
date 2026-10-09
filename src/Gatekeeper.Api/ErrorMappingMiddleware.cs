using Gatekeeper.Domain;

namespace Gatekeeper.Api;

/// <summary>Maps domain exceptions to RFC 9457 problem details.</summary>
public sealed class ErrorMappingMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (ValidationException ex)
        {
            await Results.ValidationProblem(
                ex.Errors.ToDictionary(e => e.Key, e => new[] { e.Value })).ExecuteAsync(context);
        }
        catch (NotFoundException ex)
        {
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status404NotFound).ExecuteAsync(context);
        }
        catch (ConflictException ex)
        {
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict).ExecuteAsync(context);
        }
    }
}
