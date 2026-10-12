using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

public class PagingApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _http = factory.CreateAdminClient();

    [Fact]
    public async Task Pages_are_complete_ordered_and_end_with_null_cursor()
    {
        var prefix = $"pg{Guid.NewGuid():N}"[..10];
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Created, (await _http.PostAsJsonAsync("/v1/applications", new { name = $"{prefix}-{i}" })).StatusCode);

        var names = new List<string>();
        string? cursor = null;
        var pages = 0;
        do
        {
            var url = "/v1/applications?limit=2" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}");
            var page = await _http.GetFromJsonAsync<JsonElement>(url);
            Assert.True(page.GetProperty("items").GetArrayLength() <= 2);
            names.AddRange(page.GetProperty("items").EnumerateArray().Select(a => a.GetProperty("name").GetString()!));
            cursor = page.GetProperty("nextCursor").GetString();
            pages++;
        } while (cursor is not null && pages < 100);

        var mine = names.Where(n => n.StartsWith(prefix)).ToList();
        Assert.Equal(Enumerable.Range(0, 5).Select(i => $"{prefix}-{i}"), mine);
        Assert.Equal(names.Count, names.Distinct().Count());
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=201")]
    [InlineData("limit=abc")]
    [InlineData("cursor=garbage!")]
    [InlineData("cursor=")]
    public async Task Bad_paging_parameters_are_400(string query) =>
        Assert.Equal(HttpStatusCode.BadRequest, (await _http.GetAsync($"/v1/applications?{query}")).StatusCode);
}

public class PasswordApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _http = factory.CreateAdminClient();

    private async Task<Guid> MkUser()
    {
        var n = $"pw{Guid.NewGuid():N}"[..14];
        var r = await _http.PostAsJsonAsync("/v1/users", new { username = n, email = $"{n}@example.com" });
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Set_password_accepts_valid_and_never_echoes_it()
    {
        var id = await MkUser();
        var r = await _http.PutAsJsonAsync($"/v1/users/{id}/password", new { password = "a long enough password" });
        Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
        var user = await _http.GetStringAsync($"/v1/users/{id}");
        Assert.DoesNotContain("password", user, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", user, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("short")]
    [InlineData(null)]
    public async Task Weak_or_missing_password_is_400(string? password)
    {
        var id = await MkUser();
        Assert.Equal(HttpStatusCode.BadRequest,
            (await _http.PutAsJsonAsync($"/v1/users/{id}/password", new { password })).StatusCode);
    }

    [Fact]
    public async Task Unknown_user_is_404() =>
        Assert.Equal(HttpStatusCode.NotFound,
            (await _http.PutAsJsonAsync($"/v1/users/{Guid.NewGuid()}/password", new { password = "a long enough password" })).StatusCode);
}
