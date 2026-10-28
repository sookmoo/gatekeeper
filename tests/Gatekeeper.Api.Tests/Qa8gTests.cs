using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>QA for slice 8g: edge cases of prefix validation, escaping, usable boundaries and the served OpenAPI document.</summary>
public class Qa8gTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Qa8gTests(WebApplicationFactory<Program> factory) { _factory = factory; _admin = factory.CreateAdminClient(); }

    private static string Tag() => Guid.NewGuid().ToString("N")[..8];

    private async Task<string[]> Names(string query)
    {
        var r = await _admin.GetAsync("/v1/users?" + query);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return [.. (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("items").EnumerateArray().Select(u => u.GetProperty("username").GetString()!)];
    }

    [Theory]
    [InlineData("%0A")]            // lone newline + padding below
    [InlineData("ab%0Acd")]
    [InlineData("ab%0Dcd")]
    [InlineData("ab%09cd")]
    [InlineData("ab%7Fcd")]        // DEL
    [InlineData("ab%E2%80%AEcd")]  // bidi override
    public async Task Control_bidi_and_malformed_prefixes_are_400_for_both_parameters(string raw)
    {
        foreach (var p in new[] { "usernamePrefix", "emailPrefix" })
        {
            var r = await _admin.GetAsync($"/v1/users?{p}={raw}");
            Assert.True(r.StatusCode is HttpStatusCode.BadRequest, $"{p}={raw} -> {(int)r.StatusCode}");
        }
    }

    [Fact]
    public async Task Exactly_two_characters_and_exactly_256_are_accepted_257_is_not()
    {
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/users?usernamePrefix=ab")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/users?emailPrefix=" + new string('a', 256))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/users?emailPrefix=" + new string('a', 257))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/users?usernamePrefix=" + new string('a', 257))).StatusCode);
    }

    [Fact]
    public async Task Both_bad_prefixes_are_reported_together_and_validation_beats_other_filters()
    {
        var r = await _admin.GetAsync("/v1/users?usernamePrefix=a&emailPrefix=b");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var errors = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.True(errors.TryGetProperty("usernamePrefix", out _), errors.ToString());
        Assert.True(errors.TryGetProperty("emailPrefix", out _));
    }

    [Fact]
    public async Task Whitespace_only_two_character_prefix_is_accepted_and_matches_nothing_and_is_not_trimmed()
    {
        Assert.Empty(await Names("usernamePrefix=%20%20"));
        Assert.Empty(await Names("usernamePrefix=%20a"));
    }

    [Fact]
    public async Task Unicode_prefix_matches_case_insensitively()
    {
        var t = Tag();
        // usernames are restricted; use the repository to store a non-ASCII name and e-mail
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        await repo.AddAsync(new(Guid.NewGuid(), $"ünï{t}", $"Ünï{t}@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, UserKind.Person, null));
        Assert.Equal([$"ünï{t}"], await Names($"usernamePrefix={Uri.EscapeDataString("ÜN")}{""}" + "&emailPrefix=" + Uri.EscapeDataString("ünï" + t)));
    }

    [Fact]
    public async Task Escape_characters_in_the_query_string_are_literal_and_plus_is_a_space()
    {
        var t = Tag();
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        foreach (var n in new[] { $"q{t}a+b", $"q{t}a%b", $"q{t}a_b", $"q{t}axb", $"q{t}a\\b" })
            await repo.AddAsync(new(Guid.NewGuid(), n, n.Replace('\\', '-') + "@example.com", "", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, UserKind.Person, null));
        Assert.Equal([$"q{t}a%b"], await Names($"usernamePrefix=q{t}a%25"));
        Assert.Equal([$"q{t}a+b"], await Names($"usernamePrefix=q{t}a%2B"));
        Assert.Equal([$"q{t}a_b"], await Names($"usernamePrefix=q{t}a_"));
        Assert.Equal([$"q{t}a\\b"], await Names($"usernamePrefix=q{t}a%5C"));
        Assert.Empty(await Names($"usernamePrefix=q{t}a+")); // '+' decodes to a space
    }

    [Fact]
    public async Task Usable_boundary_expiry_in_the_near_future_and_past_and_the_null_cases()
    {
        var t = Tag();
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        User M(string n, DateTimeOffset? e, bool a = true) => new(Guid.NewGuid(), $"b{t}-{n}", $"{n}{t}@example.com", "", a, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, e is null ? UserKind.Person : UserKind.Test, e);
        await repo.AddAsync(M("future", DateTimeOffset.UtcNow.AddMinutes(5)));
        await repo.AddAsync(M("justpast", DateTimeOffset.UtcNow.AddSeconds(-1)));
        await repo.AddAsync(M("none", null));
        Assert.Equal([$"b{t}-future", $"b{t}-none"], await Names($"usernamePrefix=b{t}&usable=true"));
        Assert.Equal([$"b{t}-justpast"], await Names($"usernamePrefix=b{t}&usable=false"));
        // case variants of the bool and repeated parameters
        Assert.Equal(2, (await Names($"usernamePrefix=b{t}&usable=TRUE")).Length);
    }

    [Fact]
    public async Task Existing_callers_without_the_new_parameters_are_unchanged()
    {
        var t = Tag();
        var r = await _admin.PostAsJsonAsync("/v1/users", new { username = $"bc{t}", email = $"bc{t}@example.com", displayName = "" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        Assert.Contains($"bc{t}", await Names($"username=BC{t}"));
        Assert.Contains($"bc{t}", await Names($"active=true&kind=person&limit=200"));
    }

    [Fact]
    public async Task Served_document_matches_the_file_for_the_8g_additions()
    {
        var served = await _admin.GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "docs", "openapi.json"))) d = d.Parent;
        var file = JsonDocument.Parse(File.ReadAllText(Path.Combine(d!.FullName, "docs", "openapi.json"))).RootElement;
        foreach (var doc in new[] { served, file })
        {
            var get = doc.GetProperty("paths").EnumerateObject().Single(x => x.Name.TrimEnd('/') == "/v1/users").Value.GetProperty("get");
            var names = get.GetProperty("parameters").EnumerateArray().Select(p => p.GetProperty("name").GetString()).ToArray();
            Assert.Contains("usernamePrefix", names); Assert.Contains("emailPrefix", names); Assert.Contains("usable", names);
            Assert.True(doc.GetProperty("components").GetProperty("schemas").GetProperty("UserRoleView").GetProperty("properties").TryGetProperty("appName", out _));
        }
    }
}
