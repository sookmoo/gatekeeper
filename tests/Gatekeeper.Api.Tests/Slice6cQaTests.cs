using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA of slice 6c: cursor edge cases at the HTTP boundary.</summary>
public class Slice6cQaTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice6cQaTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private Task<HttpResponseMessage> Raw(string query) => _admin.GetAsync("/v1/audit?" + query);
    private static string Esc(string s) => Uri.EscapeDataString(s);

    private async Task Add(string actor, string target, DateTimeOffset at, Guid id) =>
        await _factory.Services.GetRequiredService<IAuditRepository>().AppendAsync(new AuditEvent(id, at, actor, "qa.x", target, "success", null, null));

    private static string[] Targets(JsonElement page) => page.GetProperty("items").EnumerateArray().Select(e => e.GetProperty("target").GetString()!).ToArray();

    [Fact]
    public async Task Walk_over_rows_one_microsecond_apart_and_ties_with_every_page_size_is_exact()
    {
        var actor = "q-" + Guid.NewGuid().ToString("N")[..12];
        var t = new DateTimeOffset(2026, 4, 1, 0, 0, 0, TimeSpan.Zero);
        var ids = new[] { "80000000-0000-0000-0000-000000000000", "00000001-0000-0000-0000-000000000000", "ffffffff-0000-0000-0000-000000000000", "7fffffff-ffff-ffff-ffff-ffffffffffff" }.Select(Guid.Parse).ToArray();
        for (var i = 0; i < ids.Length; i++) await Add(actor, $"s{i}", t, ids[i]);
        await Add(actor, "after", t.AddTicks(10), Guid.NewGuid());
        await Add(actor, "before", t.AddTicks(-10), Guid.NewGuid());
        var all = Targets(await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=100"));
        Assert.Equal(6, all.Length);
        Assert.Equal("after", all[0]); Assert.Equal("before", all[^1]);
        foreach (var size in new[] { 1, 2, 3, 5, 6, 7 })
        {
            var walked = new List<string>();
            string? cursor = null;
            for (var guard = 0; guard < 20; guard++)
            {
                var page = await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit={size}" + (cursor is null ? "" : "&cursor=" + Esc(cursor)));
                walked.AddRange(Targets(page));
                var next = page.GetProperty("nextCursor");
                if (next.ValueKind == JsonValueKind.Null) break;
                cursor = next.GetString();
            }
            Assert.Equal(all, walked);
        }
    }

    [Fact]
    public async Task Exactly_a_full_last_page_has_no_cursor_and_an_empty_result_has_none()
    {
        var actor = "q-" + Guid.NewGuid().ToString("N")[..12];
        for (var i = 0; i < 4; i++) await Add(actor, $"x{i}", DateTimeOffset.UtcNow.AddTicks(-i * 10), Guid.NewGuid());
        var page = await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&limit=4");
        Assert.Equal(4, Targets(page).Length);
        Assert.Equal(JsonValueKind.Null, page.GetProperty("nextCursor").ValueKind);
        var none = await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor=nobody-{actor}&limit=1");
        Assert.Empty(Targets(none));
        Assert.Equal(JsonValueKind.Null, none.GetProperty("nextCursor").ValueKind);
    }

    [Fact]
    public async Task Extreme_but_canonical_cursors_work_and_noncanonical_forms_are_400()
    {
        var actor = "q-" + Guid.NewGuid().ToString("N")[..12];
        await Add(actor, "only", DateTimeOffset.UtcNow, Guid.NewGuid());
        var min = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(0, TimeSpan.Zero), Guid.Empty));
        var max = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(3_155_378_975_999_999_990L, TimeSpan.Zero), new Guid(Enumerable.Repeat((byte)0xff, 16).ToArray())));
        Assert.Empty(Targets(await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&cursor={Esc(min)}")));
        Assert.Equal(["only"], Targets(await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={actor}&cursor={Esc(max)}")));

        var real = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(DateTimeOffset.UtcNow.Ticks / 10 * 10, TimeSpan.Zero), Guid.NewGuid()));
        var bad = new List<string>
        {
            " " + real, real + " ", real + "\n", real + "\t", real[..10] + " " + real[10..], real + "==", real + "=",
            real.Replace('-', '+').Replace('_', '/') + "A", "%EF%BC%A1" , new string('а', 34), real.ToUpperInvariant() == real ? real + "x" : real.ToUpperInvariant(),
            real.ToLowerInvariant() == real ? real + "x" : real.ToLowerInvariant(),
        };
        // non-canonical trailing bits: the last base64 char of 25 bytes carries 2 spare bits, so 3 other letters decode to the same bytes
        var last = real[^1];
        foreach (var c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
            if (c != last) bad.Add(real[..^1] + c);
        foreach (var c in bad)
        {
            var r = await Raw("cursor=" + Esc(c));
            var code = (int)r.StatusCode;
            // a changed final character is only a different valid key if the spare bits are zero; those that decode must not be 500
            Assert.True(code is 200 or 400, $"'{c}' -> {code}");
        }
        // forms that must be refused outright
        foreach (var c in new[] { " " + real, real + " ", real + "==", real + "=", real + "\n", real[..10] + " " + real[10..] })
            Assert.Equal(HttpStatusCode.BadRequest, (await Raw("cursor=" + Esc(c))).StatusCode);
        // spare-bit variants: only the canonical one decodes to a key; count how many 200 (expected: the one with the same 6-bit group, i.e. 1 of 64 is real, others differ in data)
        var ok = 0;
        foreach (var c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
            if ((await Raw("cursor=" + Esc(real[..^1] + c))).StatusCode == HttpStatusCode.OK) ok++;
        Assert.True(ok <= 4, $"{ok} variants of the last character decoded; only the 4 that carry distinct data bits may");
    }

    [Fact]
    public async Task Repeated_and_unusual_query_forms_do_not_500()
    {
        var real = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(DateTimeOffset.UtcNow.Ticks / 10 * 10, TimeSpan.Zero), Guid.NewGuid()));
        foreach (var q in new[]
        {
            $"cursor={real}&cursor={real}", $"cursor={real},{real}", $"cursor={real}&limit=0", $"cursor={real}&limit=201", "limit=-1", "limit=abc",
            $"cursor={real.Replace('-', '+')}", "cursor=%00", "cursor=" + Esc(real + "\0"),
        })
        {
            var code = (int)(await Raw(q)).StatusCode;
            Assert.True(code is 200 or 400, $"{q} -> {code}");
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await Raw($"cursor={real}&limit=0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Raw($"cursor={real}&limit=201")).StatusCode);
    }

    [Fact]
    public async Task Keyset_cursors_are_refused_by_every_other_list_and_offset_cursors_by_audit()
    {
        var key = AuditPageQuery.Encode(new AuditKey(new DateTimeOffset(DateTimeOffset.UtcNow.Ticks / 10 * 10, TimeSpan.Zero), Guid.NewGuid()));
        foreach (var path in new[] { "/v1/applications", "/v1/users", "/v1/clients", "/v1/roles" })
        {
            var code = (await _admin.GetAsync(path + "?cursor=" + Esc(key))).StatusCode;
            Assert.True(code is HttpStatusCode.BadRequest or HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed, $"{path} -> {(int)code}");
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await Raw("cursor=" + Esc(Convert.ToBase64String("o5"u8.ToArray()).TrimEnd((char)61).Replace((char)43,(char)45).Replace((char)47,(char)95)))).StatusCode);
    }

    [Fact]
    public async Task Replay_of_a_cursor_under_another_filter_is_a_position_only()
    {
        var a = "q-" + Guid.NewGuid().ToString("N")[..12];
        var b = "q-" + Guid.NewGuid().ToString("N")[..12];
        var t = new DateTimeOffset(2026, 4, 2, 0, 0, 0, TimeSpan.Zero);
        for (var i = 0; i < 4; i++) { await Add(a, $"a{i}", t.AddSeconds(i * 2), Guid.NewGuid()); await Add(b, $"b{i}", t.AddSeconds(i * 2 + 1), Guid.NewGuid()); }
        var first = await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={a}&limit=2");
        var c = first.GetProperty("nextCursor").GetString()!;
        // a's cursor sits at a1 (t+2s); b's rows older than that are b0 (t+1s) only
        Assert.Equal(["b1", "b0"], Targets(await _admin.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={b}&cursor={Esc(c)}")));
    }
}
