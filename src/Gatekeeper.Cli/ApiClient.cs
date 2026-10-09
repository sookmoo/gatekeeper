using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Gatekeeper.Cli;

/// <summary>Failure with a CLI exit code: 1 error, 2 not found, 3 conflict, 4 unreachable.</summary>
public sealed class CliException(int exitCode, string message) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

public sealed class ApiClient(HttpClient http)
{
    public Task<JsonElement> GetAsync(string path) => SendAsync(HttpMethod.Get, path, null);

    public Task<JsonElement> PostAsync(string path, object body) => SendAsync(HttpMethod.Post, path, body);

    public Task<JsonElement> PutAsync(string path, object? body = null) => SendAsync(HttpMethod.Put, path, body);

    public Task<JsonElement> DeleteAsync(string path) => SendAsync(HttpMethod.Delete, path, null);

    private async Task<JsonElement> SendAsync(HttpMethod method, string path, object? body)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);

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

            var message = Describe(text) ?? response.ReasonPhrase ?? response.StatusCode.ToString();
            var code = response.StatusCode switch
            {
                HttpStatusCode.NotFound => 2,
                HttpStatusCode.Conflict => 3,
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
