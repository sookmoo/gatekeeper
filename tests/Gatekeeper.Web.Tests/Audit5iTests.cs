extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

public class Audit5iTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Audit5iTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<HttpClient> ApiAdminAsync(WebFixture f)
    {
        var c = f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private static async Task<Guid> AdminIdAsync(HttpClient api) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/users?username={WebFixture.AdminName}")).GetProperty("items")[0].GetProperty("id").GetGuid();

    private static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };

    private static WebFixture With(Func<HttpRequestMessage, HttpResponseMessage?> rule)
    {
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), rule)));
        return f;
    }

    private static string Row(string at, string actor, string action, string? target, string outcome, string? detail, string? address, string? cursor = null)
    {
        string S(string? v) => v is null ? "null" : JsonSerializer.Serialize(v);
        return $"{{\"items\":[{{\"id\":\"{Guid.NewGuid()}\",\"at\":\"{at}\",\"actor\":{S(actor)},\"action\":{S(action)},\"target\":{S(target)},\"outcome\":{S(outcome)},\"detail\":{S(detail)},\"address\":{S(address)}}}],\"nextCursor\":{S(cursor)}}}";
    }

    [Fact]
    public async Task Page_needs_a_session_and_has_no_post_form()
    {
        var resp = await _f.Browser().GetAsync("/Audit");
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("/Login", resp.Headers.Location?.OriginalString);

        var b = await _f.SignedInAsync();
        var page = await b.GetAsync("/Audit");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("no-store", page.Headers.CacheControl?.ToString());
        var html = await page.Content.ReadAsStringAsync();
        // the only POST form is the sign-out button of the layout; the page's own filter form is GET
        var posts = Regex.Matches(html, "<form[^>]*method=\"post\"[^>]*>", RegexOptions.IgnoreCase);
        Assert.Single(posts);
        Assert.Contains("/Logout", posts[0].Value);
        Assert.Contains("<form method=\"get\" action=\"/Audit\"", html);
        Assert.Contains("href=\"/Audit\"", html);
        // a crafted POST is a plain 404
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, "/Audit", new(), "/Applications")).StatusCode);
    }

    [Fact]
    public async Task An_admin_action_shows_with_the_admin_as_actor_and_filters_match_exactly()
    {
        var api = await ApiAdminAsync(_f);
        var adminId = await AdminIdAsync(api);
        var b = await _f.SignedInAsync();
        var created = await api.PostAsJsonAsync("/v1/applications", new { name = Unique("auditapp") });
        var app = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();

        // the admin deletes it through the UI: the row names the admin, not the web server
        var del = await WebFixture.PostFormAsync(b, $"/Applications/Delete/{app}", new());
        Assert.Equal(HttpStatusCode.Redirect, del.StatusCode);

        var action = $"DELETE /v1/applications/{{id}}";
        var url = $"/Audit?actor={adminId}&action=" + Uri.EscapeDataString(action);
        var html = await b.GetStringAsync(url);
        Assert.Contains($"id={app}", html);
        Assert.Contains(adminId.ToString(), html);
        Assert.Contains("DELETE /v1/applications/{id}", html);
        Assert.Contains("success", html);
        Assert.Contains("UTC", html);
        Assert.DoesNotContain("No events.", html);
        // the filter values are kept in the form
        Assert.Contains($"value=\"{adminId}\"", html);

        // exact match: a prefix, another case or another actor find nothing
        foreach (var q in new[] { $"actor={adminId}&action=" + Uri.EscapeDataString("DELETE /v1/applications"), $"actor={adminId}&action=" + Uri.EscapeDataString(action.ToLowerInvariant()),
                     $"actor={Guid.NewGuid()}&action=" + Uri.EscapeDataString(action), "actor=" + adminId.ToString()[..8] })
            Assert.Contains("No events.", await b.GetStringAsync("/Audit?" + q));
    }

    [Fact]
    public async Task Paging_follows_the_cursor_and_keeps_the_filters()
    {
        var api = await ApiAdminAsync(_f);
        var adminId = await AdminIdAsync(api);
        var b = await _f.SignedInAsync();
        var created = await api.PostAsJsonAsync("/v1/applications", new { name = Unique("pageapp") });
        var app = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        for (var i = 0; i < 55; i++)
            Assert.Equal(HttpStatusCode.OK, (await api.PatchAsJsonAsync($"/v1/applications/{app}", new { name = Unique("p" + i) })).StatusCode);

        var action = "PATCH /v1/applications/{id}";
        var before = 0; // rows matching now, counted through the API
        string? walk = null;
        do
        {
            var p = await api.GetFromJsonAsync<JsonElement>($"/v1/audit?actor={adminId}&action=" + Uri.EscapeDataString(action) + "&limit=200" + (walk is null ? "" : "&cursor=" + Uri.EscapeDataString(walk)));
            before += p.GetProperty("items").GetArrayLength();
            walk = p.GetProperty("nextCursor").GetString();
        } while (walk is not null);
        var first = await b.GetStringAsync($"/Audit?actor={adminId}&action=" + Uri.EscapeDataString(action));
        Assert.Equal(50, Regex.Matches(first, "<tr>").Count - 1);
        var link = WebUtility.HtmlDecode(Regex.Match(first, "<a href=\"([^\"]*cursor=[^\"]*)\">Next page</a>").Groups[1].Value);
        Assert.StartsWith($"/Audit?actor={adminId}&action=PATCH%20%2Fv1%2Fapplications%2F%7Bid%7D&cursor=", link);
        for (var i = 0; i < 3; i++) await api.PatchAsJsonAsync($"/v1/applications/{app}", new { name = Unique("late" + i) }); // newer events arrive between the pages
        var second = await b.GetStringAsync(link);
        var rows = Regex.Matches(second, "<tr>").Count - 1;
        Assert.Equal(before - 50, rows); // no repeats of page 1 and no gaps
        Assert.Contains("PATCH /v1/applications/{id}", second);

        // an edited cursor falls back to the first page, filters kept
        var bad = await b.GetAsync($"/Audit?actor={adminId}&cursor=garbage");
        Assert.Equal(HttpStatusCode.Redirect, bad.StatusCode);
        Assert.Equal($"/Audit?actor={adminId}", bad.Headers.Location?.OriginalString);
        var bad2 = await b.GetAsync("/Audit?cursor=garbage");
        Assert.Equal("/Audit", bad2.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Browser_query_strings_work()
    {
        var seen = new List<string>();
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath != "/v1/audit") return null;
            seen.Add(r.RequestUri.Query);
            return Json("{\"items\":[],\"nextCursor\":null}");
        });
        var b = await f.SignedInAsync();
        // what a browser sends from the empty form
        var html = await b.GetStringAsync("/Audit?actor=&action=");
        Assert.Contains("No events.", html);
        Assert.Equal("?limit=50", seen[^1]);
        // a repeated parameter, a plus sign, percent-encoding and unicode
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=a&actor=b")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=a+b&action=POST%20%2Fv1%2Fusers")).StatusCode);
        Assert.Equal("?limit=50&actor=a%20b&action=POST%20%2Fv1%2Fusers", seen[^1]);
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Audit?actor=%C3%A5%E4%B8%AD&action=%00")).StatusCode);
        // a filter longer than any stored field matches nothing without a call
        var calls = seen.Count;
        Assert.Contains("No events.", await b.GetStringAsync("/Audit?actor=" + new string('x', 203)));
        Assert.Equal(calls, seen.Count);
    }

    [Fact]
    public async Task Hostile_text_is_encoded_and_long_fields_are_capped()
    {
        var hostile = "<script>alert(1)</script><img src=x onerror=1>\"'";
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit"
            ? Json(Row("2026-01-02T03:04:05Z", hostile, hostile, hostile, hostile, hostile + new string('y', 5000), hostile, hostile))
            : null);
        var b = await f.SignedInAsync();
        var html = await b.GetStringAsync("/Audit?actor=" + Uri.EscapeDataString(hostile) + "&action=" + Uri.EscapeDataString(hostile));
        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("2026-01-02 03:04:05", html);
        Assert.DoesNotContain(new string('y', 300), html);
        var tag = Regex.Match(html, "<input[^>]*name=\"actor\"[^>]*>").Value;
        Assert.DoesNotContain("\"'", tag.Replace("&quot;", ""));
        var link = Regex.Match(html, "href=\"(/Audit\\?[^\"]*cursor=[^\"]*)\"").Groups[1].Value;
        Assert.NotEmpty(link);
        Assert.DoesNotContain("<", link);
        Assert.Contains("actor=%3Cscript%3E", link);
        Assert.Contains("action=%3Cscript%3E", link);
    }

    [Fact]
    public async Task Empty_result_says_no_events()
    {
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit" ? Json("{\"items\":[],\"nextCursor\":null}") : null);
        var html = await (await f.SignedInAsync()).GetStringAsync("/Audit?actor=nobody");
        Assert.Contains("No events.", html);
        Assert.DoesNotContain("<table", html);
        Assert.DoesNotContain("Next page", html);
    }

    [Theory]
    [InlineData(403, HttpStatusCode.Forbidden, "not allowed")]
    [InlineData(429, HttpStatusCode.TooManyRequests, "Too many attempts")]
    [InlineData(503, HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData(500, HttpStatusCode.BadGateway, "could not complete")]
    public async Task Api_failures_get_a_fixed_text_and_no_detail(int api, HttpStatusCode expected, string text)
    {
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit"
            ? Json("{\"detail\":\"secret-internal\"}", (HttpStatusCode)api)
            : null);
        var resp = await (await f.SignedInAsync()).GetAsync("/Audit?actor=x");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(expected, resp.StatusCode);
        Assert.Contains(text, body);
        Assert.DoesNotContain("secret-internal", body);
    }

    [Fact]
    public async Task A_bad_request_shows_a_fixed_text_and_an_ended_session_goes_to_sign_in()
    {
        var mode = 400;
        using var f = With(r => r.RequestUri!.AbsolutePath == "/v1/audit"
            ? Json("{\"detail\":\"secret-internal <b>\"}", (HttpStatusCode)mode)
            : null);
        var b = await f.SignedInAsync();
        var resp = await b.GetAsync("/Audit?actor=x");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("Could not list audit events.", body);
        Assert.DoesNotContain("secret-internal", body);

        mode = 401;
        var ended = await b.GetAsync("/Audit");
        Assert.Equal(HttpStatusCode.SeeOther, ended.StatusCode);
        Assert.Equal("/Login?ended=1", ended.Headers.Location?.OriginalString);
    }

    [Theory]
    [InlineData("a+b")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task A_malformed_cursor_goes_to_the_first_page_without_an_api_call(string cursor)
    {
        var calls = 0;
        using var f = With(r =>
        {
            if (r.RequestUri!.AbsolutePath == "/v1/audit") calls++;
            return null;
        });
        var b = await f.SignedInAsync();
        var resp = await b.GetAsync("/Audit?action=X&cursor=" + Uri.EscapeDataString(cursor));
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("/Audit?action=X", resp.Headers.Location?.OriginalString);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void The_display_cap_does_not_split_a_surrogate_pair()
    {
        var text = new string('a', 199) + "\U0001F600" + new string('b', 50);
        var shown = Pages.Audit.IndexModel.Cap(text);
        Assert.Equal(new string('a', 199) + "...", shown);
        Assert.Equal(new string('a', 200) + "...", Pages.Audit.IndexModel.Cap(new string('a', 200) + "bb"));
    }
}
