using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 7e QA: the forwarded-header warning at its edges.</summary>
public class Qa7eProxyWarningTests
{
    private static IPAddress Ip(string s) => IPAddress.Parse(s);

    [Fact]
    public void Exactly_one_interval_later_warns_again_and_just_before_does_not()
    {
        var time = new FakeTimeProvider();
        var w = new ForwardedHeaderWarning([], time, TimeSpan.FromMinutes(10));
        Assert.Equal("10.0.0.2", w.Check(Ip("10.0.0.2"), true));
        time.Advance(TimeSpan.FromMinutes(10) - TimeSpan.FromTicks(1));
        Assert.Null(w.Check(Ip("10.0.0.2"), true));
        time.Advance(TimeSpan.FromTicks(1));
        Assert.Equal("10.0.0.2", w.Check(Ip("10.0.0.2"), true));
    }

    [Fact]
    public void The_limit_is_per_peer()
    {
        var time = new FakeTimeProvider();
        var w = new ForwardedHeaderWarning([], time);
        Assert.Equal("10.0.0.2", w.Check(Ip("10.0.0.2"), true));
        Assert.Equal("10.0.0.3", w.Check(Ip("10.0.0.3"), true));
        Assert.Null(w.Check(Ip("10.0.0.2"), true));
        Assert.Null(w.Check(Ip("10.0.0.3"), true));
        time.Advance(TimeSpan.FromHours(1));
        Assert.Equal("10.0.0.3", w.Check(Ip("10.0.0.3"), true));
    }

    [Fact]
    public void At_most_sixteen_peers_are_remembered_and_further_new_peers_are_dropped_silently()
    {
        var time = new FakeTimeProvider();
        var w = new ForwardedHeaderWarning([], time);
        for (var i = 1; i <= ForwardedHeaderWarning.MaxPeers; i++) Assert.NotNull(w.Check(Ip("10.0.1." + i), true));
        Assert.Null(w.Check(Ip("10.0.2.1"), true));
        Assert.Null(w.Check(Ip("10.0.2.1"), true));
        Assert.Null(w.Check(Ip("10.0.1.1"), true)); // known peers keep their own limit
        time.Advance(TimeSpan.FromHours(1));
        Assert.Equal("10.0.2.1", w.Check(Ip("10.0.2.1"), true)); // expired entries make room
    }

    [Fact]
    public void A_trusted_or_header_less_request_does_not_use_up_the_warning()
    {
        var w = new ForwardedHeaderWarning([Ip("10.0.0.1")], new FakeTimeProvider());
        Assert.Null(w.Check(Ip("10.0.0.1"), true));
        Assert.Null(w.Check(Ip("10.0.0.2"), false));
        Assert.Equal("10.0.0.2", w.Check(Ip("10.0.0.2"), true));
    }

    [Theory]
    [InlineData("::ffff:10.0.0.1", "10.0.0.1")]
    [InlineData("10.0.0.1", "10.0.0.1")]
    [InlineData("fd00::1", "fd00::1")]
    public void Trusted_peers_match_across_ipv4_mapping(string peer, string trusted)
    {
        Assert.Null(new ForwardedHeaderWarning([Ip(trusted)]).Check(Ip(peer), true));
    }

    [Fact]
    public void A_mapped_untrusted_peer_is_named_in_plain_ipv4_form_and_an_unknown_peer_still_warns()
    {
        Assert.Equal("10.0.0.9", new ForwardedHeaderWarning([Ip("10.0.0.1")]).Check(Ip("::ffff:10.0.0.9"), true));
        Assert.Equal("unknown", new ForwardedHeaderWarning([Ip("10.0.0.1")]).Check(null, true));
    }

    [Fact]
    public async Task Racing_requests_produce_exactly_one_warning_per_interval()
    {
        for (var round = 0; round < 20; round++)
        {
            var w = new ForwardedHeaderWarning([], new FakeTimeProvider());
            var hits = 0;
            await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(() => { if (w.Check(Ip("10.0.0.2"), true) is not null) Interlocked.Increment(ref hits); })));
            Assert.Equal(1, hits);
        }
    }

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
        public readonly List<string> Lines = [];
        public ILogger CreateLogger(string c) => this;
        public IDisposable? BeginScope<T>(T state) where T : notnull => null;
        public bool IsEnabled(LogLevel l) => true;
        public void Log<T>(LogLevel l, EventId id, T s, Exception? ex, Func<T, Exception?, string> f) { lock (Lines) Lines.Add($"{l}|{f(s, ex)}"); }
        public void Dispose() { }
    }

    private static WebApplicationFactory<Program> Factory(string? trusted, Capture log) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            if (trusted is not null) b.UseSetting("Auth:TrustedProxies", trusted);
            b.ConfigureServices(s =>
            {
                s.AddTransient<IStartupFilter, PeerFilter>();
                s.AddSingleton<ILoggerProvider>(log);
            });
        });

    [Fact]
    public async Task Neither_header_values_nor_forged_text_reach_the_log_and_several_header_lines_warn_once()
    {
        var log = new Capture();
        using var f = Factory("10.0.0.1", log);
        var c = f.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        req.Headers.Add("X-Test-Peer", "10.0.0.2");
        req.Headers.Add("X-Forwarded-For", ["198.51.100.77", "\"Warning|FORGED-ENTRY\" 192.0.2.5"]);
        await c.SendAsync(req);
        lock (log.Lines)
        {
            var mine = log.Lines.Where(l => l.Contains("X-Forwarded-For")).ToList();
            var w = Assert.Single(mine);
            Assert.StartsWith("Warning|", w);
            Assert.Contains("10.0.0.2", w);
            Assert.DoesNotContain(log.Lines, l => l.Contains("198.51.100.77") || l.Contains("FORGED") || l.Contains("192.0.2.5"));
        }
    }

    [Fact]
    public async Task A_mapped_ipv6_form_of_the_trusted_peer_does_not_warn()
    {
        var log = new Capture();
        using var f = Factory("10.0.0.1", log);
        using var req = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        req.Headers.Add("X-Test-Peer", "::ffff:10.0.0.1");
        req.Headers.Add("X-Forwarded-For", "203.0.113.9");
        await f.CreateClient().SendAsync(req);
        lock (log.Lines) Assert.DoesNotContain(log.Lines, l => l.Contains("X-Forwarded-For"));
    }

    [Fact]
    public async Task The_warning_does_not_change_the_response()
    {
        var log = new Capture();
        using var f = Factory(null, log);
        using var plain = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        using var forwarded = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        forwarded.Headers.Add("X-Forwarded-For", "203.0.113.9");
        var c = f.CreateClient();
        Assert.Equal((await c.SendAsync(plain)).StatusCode, (await c.SendAsync(forwarded)).StatusCode);
    }
}
