using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>User kinds over HTTP: create, change, filter, the admin rule, the kind claim and expiry.</summary>
public class UserKindApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct horse battery";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _admin;

    public UserKindApiTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _admin = factory.CreateAdminClient();
    }

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<JsonElement> Ok(HttpResponseMessage r)
    {
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private Task<JsonElement> CreateUser(object body) => Ok(_admin.PostAsJsonAsync("/v1/users", body).GetAwaiter().GetResult());

    private static object NewUser(string name, string? kind = null, DateTimeOffset? expires = null) =>
        new { username = name, email = $"{name}@example.com", kind, expiresAt = expires };

    /// <summary>An application with a role held by the given user, with a password set.</summary>
    private async Task<string> GiveAccess(Guid userId)
    {
        var app = Unique("app");
        var appId = (await Ok(await _admin.PostAsJsonAsync("/v1/applications", new { name = app }))).GetProperty("id").GetGuid();
        var role = (await Ok(await _admin.PostAsJsonAsync($"/v1/applications/{appId}/roles", new { name = "reader" }))).GetProperty("id").GetGuid();
        await _admin.PutAsync($"/v1/users/{userId}/roles/{role}", null);
        await _admin.PutAsJsonAsync($"/v1/users/{userId}/password", new { password = Password });
        return app;
    }

    private static JsonElement Payload(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement;
    }

    [Fact]
    public async Task A_user_is_a_person_by_default_and_the_kind_is_a_word_in_the_response()
    {
        var u = await CreateUser(NewUser(Unique("plain")));
        Assert.Equal("person", u.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.Null, u.GetProperty("expiresAt").ValueKind);
    }

    [Fact]
    public async Task A_test_user_gets_a_default_expiry_and_a_given_one_is_kept()
    {
        var given = DateTimeOffset.UtcNow.AddDays(7);
        var a = await CreateUser(NewUser(Unique("tst"), "test"));
        var b = await CreateUser(NewUser(Unique("tst"), "test", given));
        Assert.True(a.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddDays(29));
        Assert.True(Math.Abs((b.GetProperty("expiresAt").GetDateTimeOffset() - given).TotalSeconds) < 1);
    }

    [Theory]
    [InlineData("robot", null)]
    [InlineData("person", 5)]
    [InlineData("shared", 5)]
    [InlineData("test", -1)]
    [InlineData("test", 400)]
    public async Task Bad_kind_and_expiry_combinations_are_rejected(string kind, int? days)
    {
        var r = await _admin.PostAsJsonAsync("/v1/users", NewUser(Unique("bad"), kind, days is null ? null : DateTimeOffset.UtcNow.AddDays(days.Value)));
        Assert.True(r.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity, r.StatusCode.ToString());
    }

    [Fact]
    public async Task Users_can_be_listed_by_kind_and_changed_with_patch()
    {
        var name = Unique("lst");
        var u = await CreateUser(NewUser(name, "shared"));
        var shared = await Ok(await _admin.GetAsync("/v1/users?kind=shared&limit=200"));
        Assert.Contains(shared.GetProperty("items").EnumerateArray(), x => x.GetProperty("username").GetString() == name);
        var persons = await Ok(await _admin.GetAsync("/v1/users?kind=person&limit=200"));
        Assert.DoesNotContain(persons.GetProperty("items").EnumerateArray(), x => x.GetProperty("username").GetString() == name);

        var patched = await Ok(await _admin.PatchAsync($"/v1/users/{u.GetProperty("id").GetGuid()}", JsonContent.Create(new { kind = "test" })));
        Assert.Equal("test", patched.GetProperty("kind").GetString());
        Assert.NotEqual(JsonValueKind.Null, patched.GetProperty("expiresAt").ValueKind);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.GetAsync("/v1/users?kind=robot")).StatusCode);
    }

    [Fact]
    public async Task Only_a_person_can_be_an_administrator_and_an_administrator_stays_a_person()
    {
        var roles = await Ok(await _admin.GetAsync("/v1/applications?limit=200"));
        var gk = roles.GetProperty("items").EnumerateArray().First(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var adminRole = (await Ok(await _admin.GetAsync($"/v1/applications/{gk}/roles"))).GetProperty("items").EnumerateArray()
            .First(r => r.GetProperty("name").GetString() == "admin").GetProperty("id").GetGuid();

        var shared = await CreateUser(NewUser(Unique("shr"), "shared"));
        var assign = await _admin.PutAsync($"/v1/users/{shared.GetProperty("id").GetGuid()}/roles/{adminRole}", null);
        Assert.Equal(HttpStatusCode.Conflict, assign.StatusCode);

        var person = await CreateUser(NewUser(Unique("adm")));
        var pid = person.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsync($"/v1/users/{pid}/roles/{adminRole}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PatchAsync($"/v1/users/{pid}", JsonContent.Create(new { kind = "test" }))).StatusCode);
        await _admin.DeleteAsync($"/v1/users/{pid}/roles/{adminRole}");
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsync($"/v1/users/{pid}", JsonContent.Create(new { kind = "test" }))).StatusCode);
    }

    [Fact]
    public async Task The_access_token_and_introspection_carry_the_kind()
    {
        var name = Unique("tok");
        var u = await CreateUser(NewUser(name, "test"));
        var app = await GiveAccess(u.GetProperty("id").GetGuid());
        var login = await Ok(await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = app }));
        var token = login.GetProperty("accessToken").GetString()!;
        Assert.Equal("test", Payload(token).GetProperty("kind").GetString());
    }

    [Fact]
    public async Task An_expired_test_user_is_refused_everywhere_but_keeps_its_data()
    {
        var name = Unique("exp");
        var u = await CreateUser(NewUser(name, "test"));
        var id = u.GetProperty("id").GetGuid();
        var app = await GiveAccess(id);
        var anon = _factory.CreateClient();
        var login = await Ok(await anon.PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = app, refresh = true }));
        var refresh = login.GetProperty("refreshToken").GetString()!;

        // time passes: the service refuses past dates, so set it in the store
        var repo = _factory.Services.GetRequiredService<IUserRepository>();
        var current = (await repo.GetAsync(id))!;
        await repo.UpdateAsync(current with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) });

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = app })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = refresh })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync($"/v1/users/{id}")).StatusCode);
        // an administrator can extend the account again
        var extended = await _admin.PatchAsync($"/v1/users/{id}", JsonContent.Create(new { expiresAt = DateTimeOffset.UtcNow.AddDays(5) }));
        Assert.Equal(HttpStatusCode.OK, extended.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { username = name, password = Password, application = app })).StatusCode);
    }
}
