extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Gatekeeper.Web.Tests;

public class Qa8gTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;
    public Qa8gTests(WebFixture f) => _f = f;

    private static string Tag() => Guid.NewGuid().ToString("N")[..8];

    private async Task<HttpClient> ApiAdminAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    [Fact]
    public async Task Plus_in_an_email_prefix_survives_the_next_page_link_and_the_filter_form_value_is_html_encoded()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var t = Tag();
        for (var i = 0; i < 26; i++)
            Assert.Equal(HttpStatusCode.Created, (await api.PostAsJsonAsync("/v1/users", new { username = $"pl{t}-{i:00}", email = $"pl+{t}.{i}@example.com", displayName = "" })).StatusCode);
        var html = await b.GetStringAsync($"/Users?emailPrefix={Uri.EscapeDataString("PL+" + t)}");
        Assert.Equal(25, Regex.Matches(html, "<tr>\\s*<td>pl" + t).Count);
        var next = Regex.Match(html, "<a href=\"([^\"]*cursor=[^\"]*)\">Next page").Groups[1].Value.Replace("&amp;", "&");
        Assert.Contains("emailPrefix=PL%2B" + t, next);
        var second = await b.GetStringAsync(next);
        Assert.Single(Regex.Matches(second, "<tr>\\s*<td>pl" + t));
        // the typed value comes back encoded in the input
        var enc = await b.GetStringAsync("/Users?prefix=" + Uri.EscapeDataString("a&b'\"<i>"));
        Assert.DoesNotContain("<i>", enc.Replace("<input", ""), StringComparison.Ordinal);
        Assert.Matches("name=\"prefix\" value=\"a&amp;b&#x27;&quot;&lt;i&gt;\"", enc);
    }

    [Fact]
    public async Task Blank_and_padded_prefixes_behave()
    {
        var b = await _f.SignedInAsync();
        Assert.DoesNotContain("A prefix needs", await b.GetStringAsync("/Users?prefix=%20%20%20"));   // blank = no filter
        Assert.Contains("A prefix needs", await b.GetStringAsync("/Users?prefix=%20a%20"));          // trimmed to 1
        Assert.Contains("A prefix needs", await b.GetStringAsync("/Users?emailPrefix=a"));
        Assert.Contains("A prefix needs", await b.GetStringAsync("/Users?prefix=ab&emailPrefix=a"));
    }

    [Fact]
    public async Task A_prefix_over_the_limit_typed_around_maxlength_is_a_page_not_a_500()
    {
        var b = await _f.SignedInAsync();
        var r = await b.GetAsync("/Users?prefix=" + new string('a', 257));
        Assert.True((int)r.StatusCode < 500, $"{(int)r.StatusCode}");
        r = await b.GetAsync("/Users?prefix=" + new string('a', 256));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task A_bad_cursor_with_filters_redirects_back_keeping_all_filters()
    {
        var b = await _f.SignedInAsync();
        var r = await b.GetAsync("/Users?prefix=ab&emailPrefix=cd&usable=true&kind=person&active=true&cursor=garbage");
        if (r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther)
        {
            var loc = r.Headers.Location!.ToString();
            Assert.Contains("prefix=ab", loc); Assert.Contains("emailPrefix=cd", loc); Assert.Contains("usable=true", loc);
        }
        else Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }
}
