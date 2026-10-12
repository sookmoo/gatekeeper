using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

public class PagingApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _http = factory.CreateClient();

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
