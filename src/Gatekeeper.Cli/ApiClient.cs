using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Gatekeeper.Cli;

/// <summary>Failure with a CLI exit code: 1 error, 2 not found, 3 conflict, 4 unreachable, 5 not logged in or not allowed.</summary>
public sealed class CliException(int exitCode, string message) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

public sealed class ApiClient(HttpClient http, string? bearerToken = null)
{
    public Task<JsonElement> GetAsync(string path) => SendAsync(HttpMethod.Get, path, null);

    /// <summary>GETs a paged list endpoint and follows <c>nextCursor</c> until the end; returns the items as one array.</summary>
    public async Task<JsonElement> GetListAsync(string path)
    {
        var items = new List<JsonElement>();
        string? cursor = null;
        for (var pages = 0; ; pages++)
        {
            if (pages >= MaxPages) throw new CliException(1, $"The list has more than {MaxPages} pages; refusing to print a partial result.");
            var sep = path.Contains('?') ? '&' : '?';
            var url = $"{path}{sep}limit=200" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}");
            var page = await GetAsync(url);
            if (page.ValueKind != JsonValueKind.Object || !page.TryGetProperty("items", out var arr) || arr.ValueKind != JsonValueKind.Array)
                throw new CliException(1, "Unexpected response from server (not a page).");
            items.AddRange(arr.EnumerateArray());
            if (!page.TryGetProperty("nextCursor", out var next) || next.ValueKind != JsonValueKind.String) break;
            cursor = next.GetString();
        }
        return JsonSerializer.SerializeToElement(items);
    }

    public const string LoginPath = "/v1/auth/login";

    private const int MaxPages = 500;

    public Task<JsonElement> PostAsync(string path, object body) => SendAsync(HttpMethod.Post, path, body);

    public Task<JsonElement> PutAsync(string path, object? body = null) => SendAsync(HttpMethod.Put, path, body);

    public Task<JsonElement> DeleteAsync(string path) => SendAsync(HttpMethod.Delete, path, null);

    private async Task<JsonElement> SendAsync(HttpMethod method, string path, object? body)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);
        if (bearerToken is not null) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request);
        }
        catch (HttpRequestException ex)
        {
            throw new CliException(4, $"Cannot reach Gatekeeper at {http.BaseAddress}: {ex.Message}");
        }
        catch (TaskCanceledException)
        {
            throw new CliException(4, $"Request to {http.BaseAddress} timed out.");
        }

        using (response)
        {
            var text = await response.Content.ReadAsStringAsync();
            if (response.IsSuccessStatusCode)
                return string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone();

            if ((int)response.StatusCode is >= 300 and < 400)
                throw new CliException(1, "The server answered with a redirect, which is not followed (it could forward your password to another host).");

            var message = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized when path == LoginPath => "Login failed: invalid credentials.",
                HttpStatusCode.Unauthorized when bearerToken is not null => "Your session is invalid or has expired. Run 'gk login'.",
                HttpStatusCode.Unauthorized => "Not logged in. Run 'gk login'.",
                HttpStatusCode.Forbidden => "You are not allowed to do that (administrator role required).",
                _ => Safe.Text(Describe(text) ?? response.ReasonPhrase ?? response.StatusCode.ToString()),
            };
            var code = response.StatusCode switch
            {
                HttpStatusCode.NotFound => 2,
                HttpStatusCode.Conflict => 3,
                HttpStatusCode.ServiceUnavailable => 4,
                HttpStatusCode.Unauthorized => 5,
                HttpStatusCode.Forbidden => 5,
                _ => 1,
            };
            throw new CliException(code, message);
        }
    }

    // Extracts a readable message from an RFC 9457 problem details body.
    private static string? Describe(string text)
    {
        try
        {
            var root = JsonDocument.Parse(text).RootElement;
            if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object)
            {
                var parts = errors.EnumerateObject()
                    .Select(e => $"{e.Name} {string.Join(' ', e.Value.EnumerateArray().Select(v => v.GetString()))}");
                return string.Join("; ", parts);
            }
            if (root.TryGetProperty("detail", out var detail)) return detail.GetString();
            if (root.TryGetProperty("title", out var title)) return title.GetString();
        }
        catch (JsonException)
        {
            // not JSON; fall through
        }
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }
}
