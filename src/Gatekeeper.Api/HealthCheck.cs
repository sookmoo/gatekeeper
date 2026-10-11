namespace Gatekeeper.Api;

/// <summary>Probes the local liveness endpoint; exit 0 when healthy. Used as the container HEALTHCHECK.</summary>
public static class HealthCheck
{
    public static async Task<int> RunAsync()
    {
        var url = Environment.GetEnvironmentVariable("GATEKEEPER_HEALTH_URL") ?? "http://127.0.0.1:8080/health";
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            using var response = await http.GetAsync(url);
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (Exception)
        {
            return 1;
        }
    }
}
