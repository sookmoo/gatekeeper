using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 6c: the audit list pages by keyset.</summary>
public class Slice6cApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice6cApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private Task Record(string actor, string action, string target) =>
        _factory.Services.GetRequiredService<AuditService>().RecordAsync(actor, action, target, true);

    private async Task<JsonElement> Get(string query) => await _admin.GetFromJsonAsync<JsonElement>("/v1/audit?" + query);

    private static string[] Targets(JsonElement page) => page.GetProperty("items").EnumerateArray().Select(e => e.GetProperty("target").GetString()!).ToArray();

    [Fact]
    public async Task New_events_between_pages_cause_no_repeats_and_no_gaps()
    {
        var actor = "k-" + Guid.NewGuid().ToString("N")[..12];
        for (var i = 1; i <= 5; i++) await Record(actor, "t.x", $"e{i}");
        var first = await Get($"actor={actor}&limit=2");
        Assert.Equal(["e5", "e4"], Targets(first));
        var cursor = first.GetProperty("nextCursor").GetString()!;
        Assert.Equal(34, cursor.Length);

        for (var i = 6; i <= 8; i++) await Record(actor, "t.x", $"e{i}"); // newer events arrive meanwhile
        var second = await Get($"actor={actor}&limit=2&cursor={Uri.EscapeDataString(cursor)}");
        Assert.Equal(["e3", "e2"], Targets(second));
        var third = await Get($"actor={actor}&limit=2&cursor={Uri.EscapeDataString(second.GetProperty("nextCursor").GetString()!)}");
        Assert.Equal(["e1"], Targets(third));
        Assert.Equal(JsonValueKind.Null, third.GetProperty("nextCursor").ValueKind);
        Assert.Equal(["e8", "e7", "e6", "e5", "e4", "e3", "e2", "e1"], Targets(await Get($"actor={actor}&limit=50")));
    }

    [Fact]
    public async Task Filters_and_the_cursor_combine()
    {
        var actor = "k-" + Guid.NewGuid().ToString("N")[..12];
        var other = "k-" + Guid.NewGuid().ToString("N")[..12];
        for (var i = 1; i <= 6; i++) await Record(i % 3 == 0 ? other : actor, i % 2 == 0 ? "t.even" : "t.odd", $"f{i}");
        var first = await Get($"actor={actor}&action=t.even&limit=1");
        Assert.Equal(["f4"], Targets(first)); // f6 belongs to the other actor
        var next = await Get($"actor={actor}&action=t.even&limit=1&cursor={Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!)}");
        Assert.Equal(["f2"], Targets(next));
        Assert.Equal(JsonValueKind.Null, next.GetProperty("nextCursor").ValueKind);
        // the same cursor under another filter just continues from the same position
        var swapped = await Get($"actor={actor}&action=t.odd&limit=5&cursor={Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!)}");
        Assert.Equal(["f1"], Targets(swapped));
    }

    [Fact]
    public async Task Offset_and_crafted_cursors_are_refused_with_400()
    {
        await Record("seed", "t.x", "s1");
        await Record("seed", "t.x", "s2");
        var real = (await Get("limit=1")).GetProperty("nextCursor").GetString()!;
        var key = Convert.FromBase64String(real.Replace('-', '+').Replace('_', '/') + "==");
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string Text(string t) => B64(System.Text.Encoding.ASCII.GetBytes(t));
        var wrongPrefix = (byte[])key.Clone(); wrongPrefix[0] = (byte)'o';
        var badTicks = (byte[])key.Clone(); for (var i = 1; i <= 8; i++) badTicks[i] = 0xFF;
        var cursors = new[]
        {
            Text("o0"), Text("o50"), Text("o1000000"), B64(wrongPrefix), B64(badTicks), B64(key[..24]), B64([.. key, 0]),
            real + "A", real[..^1], real + "=", real.Replace('A', 'B') == real ? real + "!" : real.Replace('A', 'B') + "!",
            "garbage!", new string('A', 34), new string('A', 100), "k", "%00",
        };
        foreach (var c in cursors)
        {
            var r = await _admin.GetAsync("/v1/audit?cursor=" + Uri.EscapeDataString(c));
            Assert.True(r.StatusCode == HttpStatusCode.BadRequest, $"cursor '{c}' -> {(int)r.StatusCode}");
            Assert.Contains("cursor", await r.Content.ReadAsStringAsync());
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/audit?cursor=")).StatusCode);
        // a keyset cursor is not accepted by the other lists, and the real one still works
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/applications?cursor=" + Uri.EscapeDataString(real))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/audit?cursor=" + Uri.EscapeDataString(real))).StatusCode);
    }

    [Fact]
    public async Task A_hand_made_canonical_cursor_works_as_a_position()
    {
        var actor = "k-" + Guid.NewGuid().ToString("N")[..12];
        await Record(actor, "t.x", "h1");
        var cursor = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(DateTimeOffset.UtcNow.AddDays(1).Date, TimeSpan.Zero), Guid.Empty));
        Assert.Equal(["h1"], Targets(await Get($"actor={actor}&cursor={Uri.EscapeDataString(cursor)}")));
        var ancient = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero), Guid.Empty));
        Assert.Empty(Targets(await Get($"actor={actor}&cursor={Uri.EscapeDataString(ancient)}")));
    }

    [Fact]
    public async Task A_cursor_between_two_microseconds_is_refused()
    {
        var t = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/audit?cursor=" + Uri.EscapeDataString(AuditPageQuery.Encode(new AuditKey(t.AddTicks(10), Guid.Empty))))).StatusCode);
        foreach (var ticks in new[] { 1, 5, 9, 11 })
        {
            var r = await _admin.GetAsync("/v1/audit?cursor=" + Uri.EscapeDataString(AuditPageQuery.Encode(new AuditKey(t.AddTicks(ticks), Guid.Empty))));
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Contains("Invalid cursor.", await r.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task The_openapi_description_names_the_keyset_cursor()
    {
        var doc = await _factory.CreateClient().GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        Assert.Contains("keyset", doc.GetProperty("paths").GetProperty("/v1/audit").GetProperty("get").GetProperty("description").GetString());
    }
}
