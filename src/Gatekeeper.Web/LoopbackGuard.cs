using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Gatekeeper.Web;

/// <summary>
/// The UI speaks plain HTTP and carries passwords and a session cookie, so it refuses to listen on anything but loopback
/// unless <c>Gatekeeper:AllowNonLoopback=true</c> (the container opt-in, paired with a loopback-only port publish or TLS in front).
/// </summary>
public static class LoopbackGuard
{
    public static void EnsureLoopbackOnly(WebApplication app)
    {
        if (app.Configuration.GetValue<bool>("Gatekeeper:AllowNonLoopback"))
        {
            app.Logger.LogWarning("Gatekeeper:AllowNonLoopback is set: the UI speaks plain HTTP. Publish it on loopback only or put TLS in front of it.");
            return;
        }

        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
        var exposed = addresses.Where(a => !IsLoopback(a)).ToList();
        if (exposed.Count == 0) return;

        app.StopAsync().GetAwaiter().GetResult();
        throw new InvalidOperationException(
            $"Refusing to listen on non-loopback address(es) {string.Join(", ", exposed)}: the UI speaks plain HTTP (set Gatekeeper:AllowNonLoopback=true only behind loopback publishing or a TLS proxy).");
    }

    private static bool IsLoopback(string address) =>
        Uri.TryCreate(address, UriKind.Absolute, out var uri)
        && (uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip)));
}
