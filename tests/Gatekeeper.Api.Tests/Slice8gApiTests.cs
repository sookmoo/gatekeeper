using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 8g: user prefix search, the usable filter and appName in the user's role list.</summary>
public class Slice8gApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Slice8gApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Tag() => Guid.NewGuid().ToString("N")[..8];

    private async Task<Guid> CreateAsync(string username, string? email = null, bool active = true)
    {
        var r = await _admin.PostAsJsonAsync("/v1/users", new { username, email = email ?? username + "@example.com", displayName = "", isActive = active });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private async Task<(JsonElement Page, string[] Names)> List(string query)
    {
        var page = await _admin.GetFromJsonAsync<JsonElement>("/v1/users?" + query);
        return (page, page.GetProperty("items").EnumerateArray().Select(u => u.GetProperty("username").GetString()!).ToArray());
    }

    [Fact]
    public async Task Username_and_email_prefix_are_case_insensitive()
    {
        var t = Tag();
        await CreateAsync($"pre{t}-alice", $"Mixed.{t}@example.com");
        await CreateAsync($"pre{t}-bob");
        await CreateAsync($"zzz{t}");
        Assert.Equal([$"pre{t}-alice", $"pre{t}-bob"], (await List($"usernamePrefix=PRE{t.ToUpperInvariant()}")).Names);
        Assert.Equal([$"pre{t}-alice"], (await List($"usernamePrefix=pre{t}-AL")).Names);
        Assert.Equal([$"pre{t}-alice"], (await List($"emailPrefix=MIXED.{t}")).Names);
        Assert.Equal([$"pre{t}-alice"], (await List($"usernamePrefix=pre{t}&emailPrefix=mixed")).Names);
        Assert.Empty((await List($"usernamePrefix=pre{t}&emailPrefix=nomatch")).Names);
        Assert.Empty((await List($"usernamePrefix=ice")).Names); // a prefix, not a substring
    }

    [Fact]
    public async Task Wildcards_and_backslash_in_the_prefix_match_themselves()
    {
        var t = Tag();
        await CreateAsync($"w{t}-a");
        await CreateAsync($"w{t}_b");
        Assert.Empty((await List("usernamePrefix=%25%25")).Names);
        Assert.Empty((await List($"usernamePrefix=w{t}%25")).Names);
        Assert.Equal([$"w{t}_b"], (await List($"usernamePrefix=w{t}_")).Names);
        Assert.Empty((await List("usernamePrefix=%5C%5C")).Names);
    }

    [Theory]
    [InlineData("usernamePrefix=a")]
    [InlineData("emailPrefix=a")]
    [InlineData("usernamePrefix=")]
    [InlineData("usernamePrefix=a%00b")]
    public async Task A_prefix_that_is_too_short_or_unclean_is_a_validation_problem(string query)
    {
        var r = await _admin.GetAsync("/v1/users?" + query);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("errors").EnumerateObject().Any());
        Assert.Equal("application/problem+json", r.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A_prefix_that_is_too_long_is_refused()
    {
        var r = await _admin.GetAsync("/v1/users?usernamePrefix=" + new string('a', Validation.MaxTextLength + 1));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/v1/users?usernamePrefix=" + new string('a', Validation.MaxTextLength))).StatusCode);
    }

    [Fact]
    public async Task Usable_separates_expired_and_disabled_users_while_active_is_unchanged()
    {
        var t = Tag();
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        User Make(string n, bool active, DateTimeOffset? exp) =>
            new(Guid.NewGuid(), $"u{t}-{n}", $"{n}{t}@example.com", "", active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, exp is null ? UserKind.Person : UserKind.Test, exp);
        await repo.AddAsync(Make("ok", true, null));
        await repo.AddAsync(Make("test", true, DateTimeOffset.UtcNow.AddDays(5)));
        await repo.AddAsync(Make("expired", true, DateTimeOffset.UtcNow.AddDays(-5)));
        await repo.AddAsync(Make("off", false, null));
        await repo.AddAsync(Make("offexp", false, DateTimeOffset.UtcNow.AddDays(-5)));
        Assert.Equal([$"u{t}-ok", $"u{t}-test"], (await List($"usernamePrefix=u{t}&usable=true")).Names);
        Assert.Equal([$"u{t}-expired", $"u{t}-off", $"u{t}-offexp"], (await List($"usernamePrefix=u{t}&usable=false")).Names);
        Assert.Equal([$"u{t}-expired", $"u{t}-ok", $"u{t}-test"], (await List($"usernamePrefix=u{t}&active=true")).Names);
        Assert.Equal([$"u{t}-off", $"u{t}-offexp"], (await List($"usernamePrefix=u{t}&active=false")).Names);
        Assert.Equal([$"u{t}-expired"], (await List($"usernamePrefix=u{t}&active=true&usable=false")).Names);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/users?usable=maybe")).StatusCode);
    }

    [Fact]
    public async Task Combined_filters_page_with_the_cursor()
    {
        var t = Tag();
        for (var i = 0; i < 5; i++) await CreateAsync($"pg{t}-{i}", $"pg{i}@corp-{t}.test", active: i != 2);
        await CreateAsync($"pg{t}-other", $"x@other-{t}.test");
        var q = $"usernamePrefix=pg{t}&emailPrefix=pg&usable=true&limit=2";
        var (first, names1) = await List(q);
        Assert.Equal([$"pg{t}-0", $"pg{t}-1"], names1);
        var (second, names2) = await List(q + "&cursor=" + Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!));
        Assert.Equal([$"pg{t}-3", $"pg{t}-4"], names2);
        Assert.Equal(JsonValueKind.Null, second.GetProperty("nextCursor").ValueKind);
    }

    [Fact]
    public async Task The_roles_of_a_user_carry_the_application_name()
    {
        var t = Tag();
        var uid = await CreateAsync($"ar{t}");
        var appA = (await (await _admin.PostAsJsonAsync("/v1/applications", new { name = $"appa-{t}" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var appB = (await (await _admin.PostAsJsonAsync("/v1/applications", new { name = $"appb-{t}" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        foreach (var (app, role) in new[] { (appA, "r1"), (appA, "r2"), (appB, "r3") })
        {
            var rid = (await (await _admin.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name = role, description = "" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{uid}/roles/{rid}", null)).StatusCode);
        }
        var items = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{uid}/roles")).GetProperty("items").EnumerateArray().ToArray();
        Assert.Equal(["r1:appa-" + t, "r2:appa-" + t, "r3:appb-" + t], items.Select(i => i.GetProperty("name").GetString() + ":" + i.GetProperty("appName").GetString()));
        Assert.All(items, i => Assert.True(i.TryGetProperty("appId", out _) && i.TryGetProperty("version", out _) && i.TryGetProperty("description", out _)));
        var filtered = (await _admin.GetFromJsonAsync<JsonElement>($"/v1/users/{uid}/roles?application={appB}")).GetProperty("items").EnumerateArray().ToArray();
        Assert.Equal(["appb-" + t], filtered.Select(i => i.GetProperty("appName").GetString()));
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/v1/users/{Guid.NewGuid()}/roles")).StatusCode);
    }
}
