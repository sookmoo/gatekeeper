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
        catch (BadHttpRequestException ex)
        {
            await Results.Problem(ex.Message, statusCode: ex.StatusCode is >= 400 and < 500 ? ex.StatusCode : StatusCodes.Status400BadRequest).ExecuteAsync(context);
        }
        catch (StoreUnavailableException ex)
        {
            context.RequestServices.GetRequiredService<ILogger<ErrorMappingMiddleware>>()
                .LogError(ex.Cause ?? ex, "Data store unavailable.");
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(context);
        }
        catch (BusyException ex)
        {
            context.Response.Headers.RetryAfter = "2";
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(context);
        }
        catch (NotFoundException ex)
        {
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status404NotFound).ExecuteAsync(context);
        }
        catch (PreconditionFailedException ex)
        {
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status412PreconditionFailed).ExecuteAsync(context);
        }
        catch (ConflictException ex)
        {
            await Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict).ExecuteAsync(context);
        }
    }
}
