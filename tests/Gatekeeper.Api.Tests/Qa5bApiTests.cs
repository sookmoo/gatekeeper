using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>QA slice 5b: edge cases of user kinds and test-user expiry.</summary>
public class Qa5bApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public Qa5bApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static StringContent Raw(string json) => new(json, Encoding.UTF8, "application/json");

    private async Task<Guid> Create(string kind, string? expiresRaw = null)
    {
        var n = Unique("q5");
        var body = $"{{\"username\":\"{n}\",\"email\":\"{n}@example.com\",\"kind\":\"{kind}\"" + (expiresRaw is null ? "" : $",\"expiresAt\":\"{expiresRaw}\"") + "}";
        var r = await _admin.PostAsync("/v1/users", Raw(body));
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Kind_filter_rejects_a_comma_list_instead_of_treating_it_as_flags()
    {
        // Enum.TryParse("person,test") yields Person|Test == Test (1), which passes IsDefined.
        var id = await Create("test");
        var r = await _admin.GetAsync("/v1/users?kind=person,test&limit=200");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task A_kind_in_the_body_that_is_a_comma_list_is_rejected()
    {
        var n = Unique("q5c");
        var r = await _admin.PostAsync("/v1/users", Raw($"{{\"username\":\"{n}\",\"email\":\"{n}@example.com\",\"kind\":\"person, test\"}}"));
        Assert.True(r.StatusCode == HttpStatusCode.BadRequest || r.StatusCode == HttpStatusCode.UnprocessableEntity,
            $"got {(int)r.StatusCode}: {await r.Content.ReadAsStringAsync()}");
    }

    [Fact]
    public async Task A_numeric_kind_in_the_body_is_rejected_like_in_the_query()
    {
        var n = Unique("q5n");
        var r = await _admin.PostAsync("/v1/users", Raw($"{{\"username\":\"{n}\",\"email\":\"{n}@example.com\",\"kind\":1}}"));
        Assert.True(r.StatusCode == HttpStatusCode.BadRequest || r.StatusCode == HttpStatusCode.UnprocessableEntity,
            $"got {(int)r.StatusCode}: {await r.Content.ReadAsStringAsync()}");
    }

    [Fact]
    public async Task A_timezone_offset_is_normalised_and_the_ceiling_is_judged_in_absolute_time()
    {
        var inside = DateTimeOffset.UtcNow.AddDays(364).ToOffset(TimeSpan.FromHours(14)).ToString("O");
        var id = await Create("test", inside);
        var u = await (await _admin.GetAsync($"/v1/users/{id}")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(Math.Abs((u.GetProperty("expiresAt").GetDateTimeOffset() - DateTimeOffset.Parse(inside)).TotalMilliseconds) < 1);
        var n = Unique("q5o");
        var over = DateTimeOffset.UtcNow.AddDays(365).AddMinutes(30).ToOffset(TimeSpan.FromHours(-12)).ToString("O");
        var r = await _admin.PostAsync("/v1/users", Raw($"{{\"username\":\"{n}\",\"email\":\"{n}@example.com\",\"kind\":\"test\",\"expiresAt\":\"{over}\"}}"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Put_without_kind_or_expiry_keeps_both_and_an_expired_user_can_be_renamed()
    {
        var id = await Create("test", DateTimeOffset.UtcNow.AddDays(3).ToString("O"));
        var before = await (await _admin.GetAsync($"/v1/users/{id}")).Content.ReadFromJsonAsync<JsonElement>();
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        var cur = (await repo.GetAsync(id))!;
        await repo.UpdateAsync(cur with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-5) });
        var n = Unique("q5r");
        var put = await _admin.PutAsync($"/v1/users/{id}", Raw($"{{\"username\":\"{n}\",\"email\":\"{n}@example.com\"}}"));
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        var after = await put.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("test", after.GetProperty("kind").GetString());
        Assert.True(after.GetProperty("expiresAt").GetDateTimeOffset() < DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task A_person_given_an_expiry_is_rejected_even_when_the_kind_is_unchanged()
    {
        var id = await Create("person");
        var r = await _admin.PatchAsync($"/v1/users/{id}", Raw($"{{\"expiresAt\":\"{DateTimeOffset.UtcNow.AddDays(3):O}\"}}"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Assigning_the_admin_role_to_a_missing_user_is_404_not_409()
    {
        var apps = await _admin.GetFromJsonAsync<JsonElement>("/v1/applications?limit=200");
        var gk = apps.GetProperty("items").EnumerateArray().First(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var roles = await _admin.GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles");
        var role = roles.GetProperty("items").EnumerateArray().First(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsync($"/v1/users/{Guid.NewGuid()}/roles/{role}", null)).StatusCode);
    }

    [Fact]
    public async Task Bootstrap_repair_of_a_non_person_user_changes_nothing_when_it_fails()
    {
        var id = await Create("shared");
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        var u = (await repo.GetAsync(id))!;
        await repo.UpdateAsync(u with { IsActive = false });
        var hashBefore = (await _factory.Services.GetRequiredService<ICredentialRepository>().GetHashAsync(id));

        Exception? thrown = null;
        try { await Gatekeeper.Api.Bootstrap.CreateAdminAsync(_factory.Services, u.Username, u.Email, "bootstrap password 1"); }
        catch (Exception ex) { thrown = ex; }

        var after = (await repo.GetAsync(id))!;
        var hashAfter = (await _factory.Services.GetRequiredService<ICredentialRepository>().GetHashAsync(id));
        // Either the whole repair works, or a refusal must leave the account as it was.
        Assert.True(thrown is null || (after.IsActive == false && hashBefore == hashAfter),
            $"refused with {thrown?.GetType().Name} but IsActive False->{after.IsActive}, passwordChanged={hashBefore != hashAfter}");
    }
}
