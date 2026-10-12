using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Gatekeeper.Infrastructure.Postgres;
using Gatekeeper.Tests;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Api.Tests;

/// <summary>QA slice 4a: one web host per store ("mem" or "pg"), plus small REST helpers. Pg is skipped without GATEKEEPER_TEST_PG.</summary>
public sealed class QaEnv : IDisposable
{
    private readonly PgTestDatabase? _db;
    public WebApplicationFactory<Program> Factory { get; }
    public HttpClient Admin { get; }
    public HttpClient Anon { get; }

    public QaEnv(string store, Action<IWebHostBuilder>? configure = null)
    {
        if (store == "pg")
        {
            _db = PgTestDatabase.TryCreate();
            Skip.If(_db is null, "GATEKEEPER_TEST_PG is not set");
            using (var migrator = new ServiceCollection().AddPostgresStore(_db!.MigratorConnection).BuildServiceProvider())
                PostgresStoreExtensions.MigrateAsync(migrator).GetAwaiter().GetResult();
            _db.GrantAppAccess();
        }
        Factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            if (_db is not null)
            {
                b.UseSetting("Store:Provider", "Postgres");
                b.UseSetting("Auth:SigningKeyPem", TestKey.Pem);
                b.UseSetting("ConnectionStrings:Gatekeeper", _db.AppConnection);
            }
            configure?.Invoke(b);
        });
        Admin = Factory.CreateAdminClient();
        Anon = Factory.CreateClient();
    }

    public void Dispose()
    {
        Admin.Dispose(); Anon.Dispose(); Factory.Dispose(); _db?.Dispose();
    }

    public static IEnumerable<object[]> Stores() { yield return ["mem"]; yield return ["pg"]; }

    public async Task<Guid> Create(string url, object body, HttpClient? c = null)
    {
        var r = await (c ?? Admin).PostAsJsonAsync(url, body);
        var text = await r.Content.ReadAsStringAsync();
        Assert.True(r.StatusCode == HttpStatusCode.Created, $"POST {url} -> {(int)r.StatusCode} {text}");
        return JsonDocument.Parse(text).RootElement.GetProperty("id").GetGuid();
    }

    public Task<Guid> App(string name) => Create("/v1/applications", new { name });
    public Task<Guid> Role(Guid app, string name) => Create($"/v1/applications/{app}/roles", new { name });
    public async Task<Guid> User(string name, string? password = "correct horse battery", bool active = true)
    {
        var id = await Create("/v1/users", new { username = name, email = $"{name}@example.com", isActive = active });
        if (password is not null)
            Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password })).StatusCode);
        return id;
    }
    public async Task Assign(Guid user, Guid role) =>
        Assert.Equal(HttpStatusCode.NoContent, (await Admin.PutAsync($"/v1/users/{user}/roles/{role}", null)).StatusCode);

    public Task<HttpResponseMessage> Login(object body) => Anon.PostAsJsonAsync("/v1/auth/login", body);
    public Task<HttpResponseMessage> Login(string user, string password, string app) =>
        Anon.PostAsJsonAsync("/v1/auth/login", new { username = user, password, application = app });

    public async Task<string> LoginToken(string user, string password, string app)
    {
        var r = await Login(user, password, app);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
    }

    public HttpClient Bearer(string token)
    {
        var c = Factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    public static async Task<JsonElement> Json(HttpResponseMessage r) =>
        JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;

    public Task<HttpResponseMessage> Raw(string url, string json, string contentType = "application/json", HttpMethod? method = null)
    {
        var req = new HttpRequestMessage(method ?? HttpMethod.Post, url) { Content = new StringContent(json, Encoding.UTF8, contentType) };
        return Anon.SendAsync(req);
    }

    /// <summary>Walks every page. Returns (pages, items).</summary>
    public async Task<(List<JsonElement> Pages, List<JsonElement> Items)> Walk(string url, int limit, HttpClient? c = null)
    {
        c ??= Admin;
        var pages = new List<JsonElement>(); var items = new List<JsonElement>();
        string? cursor = null;
        do
        {
            var u = url + (url.Contains('?') ? "&" : "?") + $"limit={limit}" + (cursor is null ? "" : "&cursor=" + Uri.EscapeDataString(cursor));
            var r = await c.GetAsync(u);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var p = await Json(r);
            pages.Add(p);
            items.AddRange(p.GetProperty("items").EnumerateArray());
            cursor = p.GetProperty("nextCursor").ValueKind == JsonValueKind.Null ? null : p.GetProperty("nextCursor").GetString();
            Assert.True(pages.Count < 2000, "paging does not terminate");
        } while (cursor is not null);
        return (pages, items);
    }

    public static string Slug() => "q" + Guid.NewGuid().ToString("N")[..10];
}
