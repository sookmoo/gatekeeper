using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gatekeeper.Api.Tests;

public class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _http;

    public ApiTests(WebApplicationFactory<Program> factory)
    {
        // Each test class instance shares the factory; use unique names per test instead of resetting state.
        _http = factory.CreateClient();
    }

    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task<JsonElement> Create(string url, object body)
    {
        var response = await _http.PostAsJsonAsync(url, body);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    [Fact]
    public async Task Health_is_ok() =>
        Assert.Equal(HttpStatusCode.OK, (await _http.GetAsync("/health")).StatusCode);

    [Fact]
    public async Task Full_flow_application_role_user_assignment()
    {
        var app = await Create("/v1/applications", new { name = Unique("app") });
        var appId = app.GetProperty("id").GetGuid();
        var role = await Create($"/v1/applications/{appId}/roles", new { name = "admin", description = "all" });
        var roleId = role.GetProperty("id").GetGuid();
        var name = Unique("user");
        var user = await Create("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "U" });
        var userId = user.GetProperty("id").GetGuid();
        Assert.True(user.GetProperty("isActive").GetBoolean());

        Assert.Equal(HttpStatusCode.NoContent, (await _http.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _http.PutAsync($"/v1/users/{userId}/roles/{roleId}", null)).StatusCode);
        var roles = await _http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}/roles?application={appId}");
        Assert.Equal(1, roles.GetArrayLength());
        var none = await _http.GetFromJsonAsync<JsonElement>($"/v1/users/{userId}/roles?application={Guid.NewGuid()}");
        Assert.Equal(0, none.GetArrayLength());

        Assert.Equal(HttpStatusCode.NoContent, (await _http.DeleteAsync($"/v1/users/{userId}/roles/{roleId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _http.DeleteAsync($"/v1/users/{userId}/roles/{roleId}")).StatusCode);

        // Deleting the app removes its roles.
        Assert.Equal(HttpStatusCode.NoContent, (await _http.DeleteAsync($"/v1/applications/{appId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _http.GetAsync($"/v1/roles/{roleId}")).StatusCode);
    }

    [Fact]
    public async Task Update_and_get_user()
    {
        var name = Unique("user");
        var user = await Create("/v1/users", new { username = name, email = $"{name}@example.com" });
        var id = user.GetProperty("id").GetGuid();
        var put = await _http.PutAsJsonAsync($"/v1/users/{id}",
            new { username = name, email = $"{name}@example.com", displayName = "New", isActive = false });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        var got = await _http.GetFromJsonAsync<JsonElement>($"/v1/users/{id}");
        Assert.Equal("New", got.GetProperty("displayName").GetString());
        Assert.False(got.GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task Duplicate_returns_409_problem_details()
    {
        var name = Unique("app");
        await Create("/v1/applications", new { name });
        var again = await _http.PostAsJsonAsync("/v1/applications", new { name });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Equal("application/problem+json", again.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Invalid_input_returns_400_with_field_errors()
    {
        var response = await _http.PostAsJsonAsync("/v1/users", new { username = "Bad Name", email = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("errors").TryGetProperty("username", out _));
        Assert.True(body.GetProperty("errors").TryGetProperty("email", out _));
    }

    [Theory]
    [InlineData("/v1/applications/00000000-0000-0000-0000-000000000001")]
    [InlineData("/v1/roles/00000000-0000-0000-0000-000000000001")]
    [InlineData("/v1/users/00000000-0000-0000-0000-000000000001")]
    public async Task Unknown_ids_return_404(string url) =>
        Assert.Equal(HttpStatusCode.NotFound, (await _http.GetAsync(url)).StatusCode);

    [Fact]
    public async Task Non_guid_id_returns_404() =>
        Assert.Equal(HttpStatusCode.NotFound, (await _http.GetAsync("/v1/users/not-a-guid")).StatusCode);

    [Fact]
    public async Task Role_for_unknown_app_returns_404() =>
        Assert.Equal(HttpStatusCode.NotFound,
            (await _http.PostAsJsonAsync($"/v1/applications/{Guid.NewGuid()}/roles", new { name = "x" })).StatusCode);

    [Fact]
    public async Task Put_without_isActive_keeps_existing_value()
    {
        var name = Unique("user");
        var user = await Create("/v1/users", new { username = name, email = $"{name}@example.com", isActive = false });
        var id = user.GetProperty("id").GetGuid();
        var put = await _http.PutAsJsonAsync($"/v1/users/{id}", new { username = name, email = $"{name}@example.com" });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        Assert.False((await put.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task Malformed_json_returns_400_problem_details()
    {
        var response = await _http.PostAsync("/v1/users",
            new StringContent("{not json", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Openapi_document_is_served()
    {
        var doc = await _http.GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        Assert.True(doc.GetProperty("paths").TryGetProperty("/v1/users", out _));
    }
}
