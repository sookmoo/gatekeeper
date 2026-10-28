extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

public class Slice8gTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Slice8gTests(WebFixture f) => _f = f;

    private static string Tag() => Guid.NewGuid().ToString("N")[..8];

    private async Task<HttpClient> ApiAdminAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private static async Task<Guid> CreateAsync(HttpClient api, string username, bool active = true)
    {
        var r = await api.PostAsJsonAsync("/v1/users", new { username, email = username + "@example.com", displayName = "", isActive = active });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static string[] Names(string html) => [.. Regex.Matches(html, "<tr>\\s*<td>([^<]*)</td>").Select(m => m.Groups[1].Value)];

    [Fact]
    public async Task The_users_list_filters_by_prefix_and_usable_and_keeps_the_filters_on_the_next_page()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var t = Tag();
        for (var i = 0; i < 27; i++) await CreateAsync(api, $"wp{t}-{i:00}");
        await CreateAsync(api, $"wp{t}-off", active: false);
        await CreateAsync(api, $"other{t}");

        var html = await b.GetStringAsync($"/Users?prefix=WP{t}");
        Assert.Equal(25, Names(html).Length);
        Assert.DoesNotContain($"other{t}", html);
        var next = Regex.Match(html, "<a href=\"([^\"]*cursor=[^\"]*)\">Next page").Groups[1].Value.Replace("&amp;", "&");
        Assert.Contains($"prefix=WP{t}", next);
        var second = await b.GetStringAsync(next);
        Assert.Equal(3, Names(second).Length);

        var usable = await b.GetStringAsync($"/Users?prefix=wp{t}&usable=true");
        Assert.DoesNotContain($"wp{t}-off", usable);
        Assert.Contains("<option value=\"true\" selected", usable);
        var notUsable = await b.GetStringAsync($"/Users?prefix=wp{t}&usable=false");
        Assert.Equal([$"wp{t}-off"], Names(notUsable));

        var byEmail = await b.GetStringAsync($"/Users?emailPrefix=OTHER{t}");
        Assert.Equal([$"other{t}"], Names(byEmail));
        Assert.Contains($"value=\"WP{t}\"", await b.GetStringAsync($"/Users?prefix=WP{t}"));
    }

    [Fact]
    public async Task A_short_prefix_gets_a_message_and_a_bad_usable_value_is_ignored()
    {
        var b = await _f.SignedInAsync();
        var html = await b.GetStringAsync("/Users?prefix=a");
        Assert.Contains("A prefix needs at least 2 characters.", html);
        Assert.Empty(Names(html));
        var ignored = await b.GetStringAsync("/Users?usable=maybe");
        Assert.DoesNotContain("A prefix needs", ignored);
        Assert.DoesNotContain("maybe", ignored);
        // markup in a prefix is encoded where it is shown again
        var xss = await b.GetStringAsync("/Users?prefix=" + Uri.EscapeDataString("\"><script>x</script>"));
        Assert.DoesNotContain("<script>x", xss);
    }

    [Fact]
    public async Task The_roles_page_shows_application_names_from_the_roles_list()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync();
        var t = Tag();
        var uid = await CreateAsync(api, $"wr{t}");
        var app = (await (await api.PostAsJsonAsync("/v1/applications", new { name = $"wapp-{t}" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var role = (await (await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = "editor", description = "" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/users/{uid}/roles/{role}", null)).StatusCode);
        var html = await b.GetStringAsync($"/Users/{uid}/Roles");
        Assert.Matches($"<td>editor</td>\\s*<td>wapp-{t}</td>", html);
    }
}
