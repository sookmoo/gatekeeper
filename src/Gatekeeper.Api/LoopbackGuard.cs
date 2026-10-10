using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Gatekeeper.Api;

/// <summary>
/// The API has no authentication yet, so refuse to run if it is bound to anything but loopback
/// (for example via ASPNETCORE_URLS=http://+:8080). Remove once callers are authenticated.
/// </summary>
public static class LoopbackGuard
{
    public static void EnsureLoopbackOnly(WebApplication app)
    {
        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
        var exposed = addresses.Where(a => !IsLoopback(a)).ToList();
        if (exposed.Count == 0) return;

        app.StopAsync().GetAwaiter().GetResult();
        throw new InvalidOperationException(
            $"Refusing to listen on non-loopback address(es) {string.Join(", ", exposed)}: the API has no authentication yet.");
    }

    private static bool IsLoopback(string address) =>
        Uri.TryCreate(address, UriKind.Absolute, out var uri)
        && (uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip)));
}
