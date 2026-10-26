using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 7e: one rate-limited warning when an untrusted peer sends X-Forwarded-For.</summary>
public class Slice7eProxyWarningTests
{
    private sealed class PeerFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, n) =>
            {
                if (ctx.Request.Headers.TryGetValue("X-Test-Peer", out var peer)) ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer.ToString());
                return n();
            });
            next(app);
        };
    }

    private sealed class Capture : ILoggerProvider, ILogger
    {
        public readonly List<string> Warnings = [];
        public ILogger CreateLogger(string c) => this;
        public IDisposable? BeginScope<T>(T state) where T : notnull => null;
        public bool IsEnabled(LogLevel l) => true;
        public void Log<T>(LogLevel l, EventId id, T s, Exception? ex, Func<T, Exception?, string> f)
        {
            if (l == LogLevel.Warning && f(s, ex).Contains("X-Forwarded-For")) lock (Warnings) Warnings.Add(f(s, ex));
        }
        public void Dispose() { }
    }

    private static WebApplicationFactory<Program> Factory(string? trusted, Capture log, FakeTimeProvider time) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            if (trusted is not null) b.UseSetting("Auth:TrustedProxies", trusted);
            b.ConfigureServices(s =>
            {
                s.AddTransient<IStartupFilter, PeerFilter>();
                s.AddSingleton<ILoggerProvider>(log);
                s.AddSingleton(new ForwardedHeaderWarning(trusted is null ? [] : [IPAddress.Parse(trusted)], time));
            });
        });

    private static async Task Get(HttpClient c, string peer, string? forwarded)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        req.Headers.Add("X-Test-Peer", peer);
        if (forwarded is not null) req.Headers.Add("X-Forwarded-For", forwarded);
        await c.SendAsync(req);
    }

    [Fact]
    public async Task An_untrusted_forwarder_gives_one_warning_per_hour_naming_the_peer_not_the_header()
    {
        var log = new Capture(); var time = new FakeTimeProvider();
        using var f = Factory("10.0.0.1", log, time);
        var c = f.CreateClient();
        for (var i = 0; i < 5; i++) await Get(c, "10.0.0.2", "203.0.113.9");
        lock (log.Warnings)
        {
            var w = Assert.Single(log.Warnings);
            Assert.Contains("10.0.0.2", w);
            Assert.Contains("Auth:TrustedProxies", w);
            Assert.Contains("If that address is your reverse proxy, add it to Auth__TrustedProxies", w);
            Assert.Contains("correctly ignored", w);
            Assert.DoesNotContain("Set Auth__TrustedProxies", w);
            Assert.DoesNotContain("203.0.113.9", w);
        }
        time.Advance(TimeSpan.FromMinutes(59));
        await Get(c, "10.0.0.2", "203.0.113.9");
        lock (log.Warnings) Assert.Single(log.Warnings);
        time.Advance(TimeSpan.FromMinutes(2));
        await Get(c, "10.0.0.2", "203.0.113.9");
        lock (log.Warnings) Assert.Equal(2, log.Warnings.Count);
    }

    [Fact]
    public async Task No_warning_for_a_trusted_peer_or_without_the_header()
    {
        var log = new Capture(); var time = new FakeTimeProvider();
        using var f = Factory("10.0.0.1", log, time);
        var c = f.CreateClient();
        await Get(c, "10.0.0.1", "203.0.113.9");
        await Get(c, "10.0.0.2", null);
        lock (log.Warnings) Assert.Empty(log.Warnings);
    }

    [Fact]
    public async Task Without_any_trusted_proxy_a_forwarded_header_warns()
    {
        var log = new Capture(); var time = new FakeTimeProvider();
        using var f = Factory(null, log, time);
        await Get(f.CreateClient(), "10.0.0.2", "203.0.113.9");
        lock (log.Warnings) Assert.Single(log.Warnings);
    }

    [Fact]
    public async Task Each_peer_gets_its_own_warning_so_one_client_cannot_use_up_the_slot_of_the_proxy()
    {
        var log = new Capture(); var time = new FakeTimeProvider();
        using var f = Factory("10.0.0.1", log, time);
        var c = f.CreateClient();
        await Get(c, "10.0.0.2", "203.0.113.9");
        await Get(c, "10.0.0.3", "203.0.113.9");
        await Get(c, "10.0.0.2", "203.0.113.9");
        lock (log.Warnings)
        {
            Assert.Equal(2, log.Warnings.Count);
            Assert.Contains(log.Warnings, w => w.Contains("10.0.0.3"));
        }
    }
}
