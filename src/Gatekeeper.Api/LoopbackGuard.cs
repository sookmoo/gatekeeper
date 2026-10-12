using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Gatekeeper.Api;

/// <summary>
/// The process speaks plain HTTP, and logins carry passwords and bearer tokens, so refuse to run if it is bound
/// to anything but loopback (for example via Urls=http://+:8080) unless TLS is terminated in front of it.
/// Inside a container the process must bind a non-loopback address; that is an explicit opt-in
/// (<c>Gatekeeper:AllowNonLoopback=true</c>) which the deployment pairs with a loopback-only port publish.
/// </summary>
public static class LoopbackGuard
{
    public static void EnsureLoopbackOnly(WebApplication app)
    {
        if (app.Configuration.GetValue<bool>("Gatekeeper:AllowNonLoopback"))
        {
            app.Logger.LogWarning("Gatekeeper:AllowNonLoopback is set: the API speaks plain HTTP. Publish it on loopback only or put TLS in front of it.");
            return;
        }

        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
        var exposed = addresses.Where(a => !IsLoopback(a)).ToList();
        if (exposed.Count == 0) return;

        app.StopAsync().GetAwaiter().GetResult();
        throw new InvalidOperationException(
            $"Refusing to listen on non-loopback address(es) {string.Join(", ", exposed)}: the API speaks plain HTTP (set Gatekeeper:AllowNonLoopback=true only behind loopback publishing or a TLS proxy).");
    }

    private static bool IsLoopback(string address) =>
        Uri.TryCreate(address, UriKind.Absolute, out var uri)
        && (uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip)));
}
