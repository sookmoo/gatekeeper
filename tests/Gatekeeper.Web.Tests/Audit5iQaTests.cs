extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent QA for slice 5i (audit trail page): gaps beyond Audit5iTests. No real-time waits.</summary>
public class Audit5iQaTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Audit5iQaTests(WebFixture f) => _f = f;

    private static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };

    private static WebFixture With(Func<HttpRequestMessage, HttpResponseMessage?> rule)
    {
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), rule)));
        return f;
    }

    private static string S(string? v) => v is null ? "null" : JsonSerializer.Serialize(v);

    private static string Item(string at, string? actor, string? action, string? target, string? outcome, string? detail, string? address) =>
        $"{{\"id\":\"{Guid.NewGuid()}\",\"at\":\"{at}\",\"actor\":{S(actor)},\"action\":{S(action)},\"target\":{S(target)},\"outcome\":{S(outcome)},\"detail\":{S(detail)},\"address\":{S(address)}}}";

    private static string PageOf(string? cursor, params string[] items) => $"{{\"items\":[{string.Join(",", items)}],\"nextCursor\":{S(cursor)}}}";

    // ---------- filters ----------

    [Fact]
    public async Task Whitespace_and_unicode_filters_are_forwarded_verbatim_and_escaped()
    {
        var seen = new List<string>();
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath != "/v1/audit") return null;
            seen.Add(r.RequestUri.Query);
            return Json(PageOf(null));
        });
        var b = await f.SignedInAsync();

        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=%20x%20")).StatusCode);
        Assert.Equal("?limit=50&actor=%20x%20", seen[^1]);                       // not trimmed: the match is exact
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=%20")).StatusCode);
        Assert.Equal("?limit=50", seen[^1]);                                     // finding: MVC binding turns a whitespace-only value into null, so it is "no filter", not "match a blank actor"
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?action=%C3%A5%E4%B8%AD%F0%9F%98%80")).StatusCode);
        Assert.Equal("?limit=50&action=%C3%A5%E4%B8%AD%F0%9F%98%80", seen[^1]);
        // injection of extra query parameters through a value stays inside the value
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=" + Uri.EscapeDataString("x&limit=1&cursor=abc#frag"))).StatusCode);
        Assert.Equal("?limit=50&actor=x%26limit%3D1%26cursor%3Dabc%23frag", seen[^1]);
        // repeated parameters: the first value wins (documented here, not a crash)
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=a&actor=b&action=c&action=d")).StatusCode);
        Assert.Equal("?limit=50&actor=a&action=c", seen[^1]);
        // a parameter without value or with a different case
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor&action")).StatusCode);
        Assert.Equal("?limit=50", seen[^1]);
        // invalid UTF-8 percent sequences do not crash
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=%FF%FE&action=%ED%A0%80")).StatusCode);
    }

    [Fact]
    public async Task Filter_length_boundary_is_202_units()
    {
        var calls = 0;
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath != "/v1/audit") return null;
            calls++;
            return Json(PageOf(null));
        });
        var b = await f.SignedInAsync();
        var html = await b.GetStringAsync("/Audit?actor=" + new string('a', 202));
        Assert.Equal(1, calls);
        Assert.Contains("maxlength=\"200\"", html);
        html = await b.GetStringAsync("/Audit?action=" + new string('a', 203));
        Assert.Equal(1, calls);                         // no call
        Assert.Contains("No events.", html);
        // 100 KB filter: still a plain page, still no call
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=" + new string('a', 100_000))).StatusCode);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Control_characters_in_a_filter_match_nothing_against_the_real_api()
    {
        var b = await _f.SignedInAsync();
        foreach (var q in new[] { "actor=%00", "action=%0D%0AInjected", "actor=%1B%5B31m", "action=%E2%80%AE" })
        {
            var r = await b.GetAsync("/Audit?" + q);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Contains("No events.", await r.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task Filter_values_are_exact_against_the_real_api_for_sql_wildcards_and_case()
    {
        var b = await _f.SignedInAsync();
        foreach (var q in new[] { "actor=%25", "actor=_", "actor=anonymou%25", "action=%25", "actor=ANONYMOUS", "actor=anonymous%20", "actor=%27%20OR%20%271%27%3D%271" })
            Assert.Contains("No events.", await b.GetStringAsync("/Audit?" + q));
    }

    // ---------- cursor ----------

    [Fact]
    public async Task Garbage_tampered_and_huge_cursors_never_give_a_server_error()
    {
        var b = await _f.SignedInAsync();
        var cursors = new[]
        {
            "garbage", "!!!", "%00", "o1", "bzE", "bzE=", "bzE%3D", "bzEw", "b0E", "-1", new string('A', 33), new string('A', 5000),
            Uri.EscapeDataString("bzE\nx"), "..%2F..%2Fetc", "%E4%B8%AD", "bzFf", "b-5", "bzEyMw", // o123 (valid canonical?)
            "bzEwMDAwMDAw", // o10000000 over the max offset
            "bzEwMDAwMDA", // o1000000 at the max offset: valid but empty
        };
        foreach (var c in cursors)
        {
            var r = await b.GetAsync($"/Audit?actor=anonymous&cursor={c}");
            Assert.True((int)r.StatusCode < 500, $"cursor {c}: {(int)r.StatusCode}");
            Assert.True(r.StatusCode is HttpStatusCode.OK or HttpStatusCode.Redirect, $"cursor {c}: {(int)r.StatusCode}");
            if (r.StatusCode == HttpStatusCode.Redirect) Assert.Equal("/Audit?actor=anonymous", r.Headers.Location?.OriginalString);
        }
        // a 200 KB cursor reaches the API URL as is; against the in-process API this is a 400 -> redirect
        var huge = await b.GetAsync("/Audit?cursor=" + new string('A', 200_000));
        Assert.True(huge.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK, "huge: " + (int)huge.StatusCode);
    }

    [Fact]
    public async Task A_valid_cursor_past_the_end_shows_no_events_and_no_next_link()
    {
        var b = await _f.SignedInAsync();
        var html = await b.GetStringAsync("/Audit?cursor=bzEwMDAwMDA"); // o1000000
        Assert.Contains("No events.", html);
        Assert.DoesNotContain("Next page", html);
    }

    [Fact]
    public async Task A_real_cursor_is_accepted_and_a_tampered_copy_falls_back_to_the_first_page()
    {
        var api = _f.Api.CreateClient();
        var b = await _f.SignedInAsync();
        // enough events: each failed sign-in writes one auth.login row
        var anon = _f.Browser();
        for (var i = 0; i < 55; i++) await api.PostAsJsonAsync("/v1/auth/login", new { username = "nobody" + i, password = "x", application = "gatekeeper" });
        var first = await b.GetStringAsync("/Audit?actor=anonymous&action=auth.login");
        var link = WebUtility.HtmlDecode(Regex.Match(first, "<a href=\"([^\"]*cursor=[^\"]*)\">Next page</a>").Groups[1].Value);
        Assert.NotEmpty(link);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync(link)).StatusCode);
        var cursor = link[(link.IndexOf("cursor=", StringComparison.Ordinal) + 7)..];
        foreach (var bad in new[] { cursor + "A", cursor[..^1], cursor.ToUpperInvariant(), "x" + cursor, cursor + cursor })
        {
            var r = await b.GetAsync($"/Audit?actor=anonymous&action=auth.login&cursor={Uri.EscapeDataString(bad)}");
            if (bad.ToUpperInvariant() == cursor.ToUpperInvariant() && bad == cursor) continue;
            Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK, $"{bad}: {(int)r.StatusCode}");
            if (r.StatusCode == HttpStatusCode.Redirect) Assert.Equal("/Audit?actor=anonymous&action=auth.login", r.Headers.Location?.OriginalString);
        }
    }

    [Fact]
    public async Task The_next_link_round_trips_a_cursor_and_keeps_both_filters()
    {
        var cursors = new List<string?>();
        const string weird = "Ab_9-z"; // the API's cursors are base64url; anything else is refused by the page before a call
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath != "/v1/audit") return null;
            var q = System.Web.HttpUtility.ParseQueryString(r.RequestUri.Query);
            cursors.Add(q["cursor"]);
            return Json(PageOf(q["cursor"] is null ? weird : null, Item("2026-01-01T00:00:00Z", "a", "b", null, "success", null, null)));
        });
        var b = await f.SignedInAsync();
        var html = await b.GetStringAsync("/Audit?actor=" + Uri.EscapeDataString("x y") + "&action=" + Uri.EscapeDataString("p&q"));
        var link = WebUtility.HtmlDecode(Regex.Match(html, "<a href=\"([^\"]*cursor=[^\"]*)\">Next page</a>").Groups[1].Value);
        Assert.Equal("/Audit?actor=x%20y&action=p%26q&cursor=Ab_9-z", link);
        var second = await b.GetStringAsync(link);
        Assert.Equal(weird, cursors[^1]);                       // the API got exactly what it issued
        Assert.DoesNotContain("Next page", second);
    }

    [Fact]
    public async Task A_hostile_next_cursor_cannot_break_out_of_the_link()
    {
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit"
            ? Json(PageOf("\"><script>alert(1)</script>", Item("2026-01-01T00:00:00Z", "a", "b", null, "success", null, null)))
            : null);
        var html = await (await f.SignedInAsync()).GetStringAsync("/Audit");
        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("cursor=%22%3E%3Cscript%3E", html);
    }

    [Fact]
    public async Task A_cursor_the_api_keeps_refusing_does_not_loop()
    {
        var calls = 0;
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath != "/v1/audit") return null;
            calls++;
            return Json("{\"detail\":\"nope\"}", HttpStatusCode.BadRequest);
        });
        var b = await f.SignedInAsync();
        var first = await b.GetAsync("/Audit?actor=x&cursor=abc");
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Equal("/Audit?actor=x", first.Headers.Location?.OriginalString);
        var second = await b.GetAsync(first.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);           // the redirect target has no cursor: an error text, not another redirect
        Assert.Contains("Could not list audit events.", await second.Content.ReadAsStringAsync());
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task The_fallback_redirect_encodes_hostile_filters()
    {
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit" ? Json("{}", HttpStatusCode.BadRequest) : null);
        var b = await f.SignedInAsync();
        var hostile = "<script>\"'&\r\nSet-Cookie: x=1";
        var r = await b.GetAsync("/Audit?actor=" + Uri.EscapeDataString(hostile) + "&cursor=bad");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var loc = r.Headers.Location!.OriginalString;
        Assert.StartsWith("/Audit?actor=", loc);
        Assert.DoesNotContain("<", loc);
        Assert.DoesNotContain("\n", loc);
        Assert.False(r.Headers.Contains("Set-Cookie") && r.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("x=1")));
    }

    // ---------- rendering ----------

    [Fact]
    public async Task Null_fields_render_empty_times_are_utc_and_split_surrogates_do_not_break_the_page()
    {
        var longWithEmoji = new string('a', 199) + "\U0001F600" + new string('b', 50);
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit"
            ? Json(PageOf(null,
                Item("2026-01-02T03:04:05+05:00", "u", "act", null, "failure", null, null),
                Item("2026-01-02T03:04:05.123456Z", longWithEmoji, longWithEmoji, longWithEmoji, "success", longWithEmoji, longWithEmoji),
                Item("2026-01-02T03:04:05Z", "", "", "", "", "", "")))
            : null);
        var resp = await (await f.SignedInAsync()).GetAsync("/Audit");
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("2026-01-01 22:04:05", html);        // converted to UTC
        Assert.DoesNotContain(">null<", html);
        Assert.DoesNotContain("��", html);
        Assert.Contains("...", html);
        Assert.DoesNotContain(new string('b', 20), html);
    }

    [Fact]
    public async Task Missing_or_odd_json_shapes_from_the_api_do_not_crash_the_page()
    {
        foreach (var body in new[] { "{\"items\":[],\"nextCursor\":null}", "{\"items\":[]}", "{\"items\":[{\"id\":\"" + Guid.NewGuid() + "\",\"at\":\"2026-01-01T00:00:00Z\"}],\"nextCursor\":null}" })
        {
            using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit" ? Json(body) : null);
            var r = await (await f.SignedInAsync()).GetAsync("/Audit");
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        }
    }

    [Fact]
    public async Task The_page_has_no_write_controls_and_the_layout_links_to_it()
    {
        var b = await _f.SignedInAsync();
        var html = await b.GetStringAsync("/Audit");
        Assert.Equal(2, Regex.Matches(html, "<form", RegexOptions.IgnoreCase).Count);        // filter (GET) + sign-out (POST)
        Assert.DoesNotMatch("<(textarea|select)", html);
        Assert.DoesNotMatch("type=\"(hidden|password|checkbox)\"(?![^>]*__Request)", Regex.Replace(html, "<form[^>]*Logout.*?</form>", "", RegexOptions.Singleline | RegexOptions.IgnoreCase));
        Assert.DoesNotMatch("(?i)href=\"[^\"]*/(Delete|Edit|Create|Revoke|Clear)[^\"]*\"", html.Replace("href=\"/Audit\">Clear", ""));
        Assert.Contains("href=\"/Audit\"", await b.GetStringAsync("/Applications"));
        Assert.Contains("href=\"/Audit\"", await b.GetStringAsync("/Users"));
    }

    [Fact]
    public async Task Other_verbs_are_refused_and_an_anonymous_visit_does_not_reach_the_api()
    {
        var calls = 0;
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath == "/v1/audit") calls++;
            return null;
        });
        var anon = f.Browser();
        var r0 = await anon.GetAsync("/Audit?actor=x&action=y");
        Assert.Equal(HttpStatusCode.Redirect, r0.StatusCode);
        Assert.Equal(0, calls);

        var b = await f.SignedInAsync();
        foreach (var m in new[] { HttpMethod.Put, HttpMethod.Delete, HttpMethod.Patch })
        {
            var r = await b.SendAsync(new HttpRequestMessage(m, "/Audit"));
            Assert.True((int)r.StatusCode is >= 400 and < 500 or 302, $"{m}: {(int)r.StatusCode}");
        }
        // POST without antiforgery, and with a valid token: never a success
        var noToken = await b.PostAsync("/Audit", new FormUrlEncodedContent(new Dictionary<string, string> { ["actor"] = "x" }));
        Assert.True((int)noToken.StatusCode is >= 400 and < 500, $"no token: {(int)noToken.StatusCode}");
        var withToken = await WebFixture.PostFormAsync(b, "/Audit", new() { ["actor"] = "x" }, "/Applications");
        Assert.Equal(HttpStatusCode.NotFound, withToken.StatusCode);
        Assert.Equal(0, calls);
    }

    // ---------- error mapping ----------

    [Fact]
    public async Task Transport_failures_map_to_503_and_504_with_a_try_again_link_to_the_audit_page()
    {
        foreach (var (ex, status, text) in new (Func<Exception>, HttpStatusCode, string)[]
                 {
                     (() => new HttpRequestException("boom secret-host"), HttpStatusCode.ServiceUnavailable, "unavailable"),
                     (() => new TaskCanceledException("t"), HttpStatusCode.GatewayTimeout, "did not answer"),
                 })
        {
            using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit" ? throw ex() : null);
            var resp = await (await f.SignedInAsync()).GetAsync("/Audit?actor=x");
            var body = await resp.Content.ReadAsStringAsync();
            Assert.Equal(status, resp.StatusCode);
            Assert.Contains(text, body);
            Assert.DoesNotContain("secret-host", body);
            Assert.Contains("href=\"/Audit\"", body);
        }
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task A_400_or_404_without_a_cursor_keeps_the_filter_form_and_shows_a_fixed_error(HttpStatusCode code)
    {
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit" ? Json("{\"detail\":\"<b>leak</b>\"}", code) : null);
        var html = await (await f.SignedInAsync()).GetStringAsync("/Audit?actor=keep");
        Assert.Contains("Could not list audit events.", html);
        Assert.DoesNotContain("leak", html);
        Assert.Contains("value=\"keep\"", html);
    }

    [Fact]
    public async Task A_401_with_a_cursor_also_ends_the_session()
    {
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit" ? Json("{}", HttpStatusCode.Unauthorized) : null);
        var r = await (await f.SignedInAsync()).GetAsync("/Audit?cursor=abc");
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
    }
}
