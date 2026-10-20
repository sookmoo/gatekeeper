extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

public class Clients5hTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Clients5hTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<HttpClient> ApiAdminAsync(WebFixture f)
    {
        var c = f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    private static async Task<Guid> CreateAppAsync(HttpClient api, string name)
    {
        var r = await api.PostAsJsonAsync("/v1/applications", new { name });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<Guid> CreateRoleAsync(HttpClient api, Guid app, string name)
    {
        var r = await api.PostAsJsonAsync($"/v1/applications/{app}/roles", new { name, description = "d" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<Guid> CreateClientAsync(HttpClient api, string name, Guid app)
    {
        var r = await api.PostAsJsonAsync("/v1/clients", new { name, application = app, isActive = true });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<List<Guid>> ClientRolesAsync(HttpClient api, Guid client) =>
        (await api.GetFromJsonAsync<JsonElement>($"/v1/clients/{client}/roles?limit=200")).GetProperty("items").EnumerateArray().Select(r => r.GetProperty("id").GetGuid()).ToList();

    private static string Alert(string html) => Regex.Match(html, "<p class=\"error\" role=\"alert\">(.*?)</p>", RegexOptions.Singleline).Groups[1].Value;

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };

    [Fact]
    public async Task Pages_need_a_session_and_posts_need_the_antiforgery_token()
    {
        var anon = _f.Browser();
        var cid = Guid.NewGuid();
        foreach (var path in new[] { $"/Clients/{cid}/Roles", $"/Clients/{cid}/Roles/Add", $"/Clients/{cid}/Roles/Remove/{Guid.NewGuid()}" })
        {
            var resp = await anon.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.Equal("/Login", resp.Headers.Location?.OriginalString);
        }

        var api = await ApiAdminAsync(_f);
        var s = await _f.SignedInAsync();
        var app = await CreateAppAsync(api, Unique("csrfapp"));
        var client = await CreateClientAsync(api, Unique("csrf"), app);
        var held = await CreateRoleAsync(api, app, "reader");
        var other = await CreateRoleAsync(api, app, "writer");
        Assert.Equal(HttpStatusCode.NoContent, (await api.PutAsync($"/v1/clients/{client}/roles/{held}", null)).StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Clients/{client}/Roles/Add", new FormUrlEncodedContent(new Dictionary<string, string> { ["RoleId"] = other.ToString() }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Clients/{client}/Roles/Remove/{held}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Equal([held], await ClientRolesAsync(api, client));
        // the list has no form
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(s, $"/Clients/{client}/Roles", new(), $"/Clients/Edit/{client}")).StatusCode);
    }

    [Fact]
    public async Task A_role_can_be_added_listed_and_removed_with_confirmation()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var appName = Unique("shop");
        var app = await CreateAppAsync(api, appName);
        var client = await CreateClientAsync(api, Unique("rt"), app);
        var reader = await CreateRoleAsync(api, app, "reader");
        var writer = await CreateRoleAsync(api, app, "writer");

        Assert.Contains($"/Clients/{client}/Roles", await b.GetStringAsync("/Clients"));
        Assert.Contains($"/Clients/{client}/Roles", await b.GetStringAsync($"/Clients/Edit/{client}"));
        Assert.Contains("No roles.", await b.GetStringAsync($"/Clients/{client}/Roles"));

        var form = await b.GetStringAsync($"/Clients/{client}/Roles/Add");
        Assert.Contains($"<option value=\"{reader}\">reader</option>", form);
        Assert.Contains($"<option value=\"{writer}\">writer</option>", form);

        // real-browser-style body: antiforgery token plus the select value (and the submit button's absence)
        var added = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = reader.ToString() });
        Assert.Equal(HttpStatusCode.Redirect, added.StatusCode);
        Assert.Equal($"/Clients/{client}/Roles?done=added", added.Headers.Location?.OriginalString);
        Assert.Equal([reader], await ClientRolesAsync(api, client));

        var list = await b.GetStringAsync($"/Clients/{client}/Roles?done=added");
        Assert.Contains("Role added.", list);
        Assert.Contains("<td>reader</td>", list);
        Assert.Contains($"/Clients/{client}/Roles/Remove/{reader}", list);
        // already assigned roles are not offered again
        var again = await b.GetStringAsync($"/Clients/{client}/Roles/Add");
        Assert.DoesNotContain($"value=\"{reader}\"", again);
        Assert.Contains($"value=\"{writer}\"", again);

        // confirmation first: a GET changes nothing
        var confirm = await b.GetStringAsync($"/Clients/{client}/Roles/Remove/{reader}");
        Assert.Contains($"<strong>{appName}</strong>", confirm);
        Assert.Equal([reader], await ClientRolesAsync(api, client));
        var removed = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Remove/{reader}", new());
        Assert.Equal($"/Clients/{client}/Roles?done=removed", removed.Headers.Location?.OriginalString);
        Assert.Empty(await ClientRolesAsync(api, client));
        // removing it again: the client no longer holds it
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Clients/{client}/Roles/Remove/{reader}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Remove/{reader}", new(), $"/Clients/{client}/Roles/Add")).StatusCode);
    }

    [Fact]
    public async Task Only_roles_of_the_clients_own_application_are_offered_and_a_forced_one_shows_the_api_refusal()
    {
        var b = await _f.SignedInAsync();
        var api = await ApiAdminAsync(_f);
        var app = await CreateAppAsync(api, Unique("own"));
        var otherApp = await CreateAppAsync(api, Unique("foreign"));
        var client = await CreateClientAsync(api, Unique("scope"), app);
        var own = await CreateRoleAsync(api, app, "own-role");
        var foreign = await CreateRoleAsync(api, otherApp, "foreign-role");

        var form = await b.GetStringAsync($"/Clients/{client}/Roles/Add");
        Assert.Contains($"value=\"{own}\"", form);
        Assert.DoesNotContain($"value=\"{foreign}\"", form);
        Assert.DoesNotContain("foreign-role", form);

        var forced = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = foreign.ToString() }, $"/Clients/{client}/Roles/Add");
        Assert.Equal(HttpStatusCode.Conflict, forced.StatusCode);
        Assert.Equal("That role belongs to a different application than the client.", Alert(await forced.Content.ReadAsStringAsync()));
        Assert.Empty(await ClientRolesAsync(api, client));

        // unknown role, missing role, garbage
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = Guid.NewGuid().ToString() }, $"/Clients/{client}/Roles/Add")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new(), $"/Clients/{client}/Roles/Add")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = "nope" }, $"/Clients/{client}/Roles/Add")).StatusCode);
        Assert.Empty(await ClientRolesAsync(api, client));
        // unknown client
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Clients/{Guid.NewGuid()}/Roles")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/Clients/{Guid.NewGuid()}/Roles/Add")).StatusCode);
        // a role another client holds cannot be removed through this client's URL
        var bystander = await CreateClientAsync(api, Unique("byst"), app);
        await api.PutAsync($"/v1/clients/{bystander}/roles/{own}", null);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Remove/{own}", new(), $"/Clients/{client}/Roles")).StatusCode);
        Assert.Equal([own], await ClientRolesAsync(api, bystander));
    }

    [Fact]
    public async Task Hostile_text_is_encoded()
    {
        var hostile = "<script>alert(1)</script><img src=x onerror=1>\"'";
        var clientId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            var h = JsonSerializer.Serialize(hostile);
            var role = $"{{\"id\":\"{roleId}\",\"appId\":\"{appId}\",\"name\":{h},\"description\":{h}}}";
            if (path == $"/v1/clients/{clientId}") return Json($"{{\"id\":\"{clientId}\",\"name\":{h},\"appId\":\"{appId}\",\"isActive\":true,\"createdAt\":\"2026-01-01T00:00:00Z\",\"updatedAt\":\"2026-01-01T00:00:00Z\"}}");
            if (path == $"/v1/applications/{appId}") return Json($"{{\"id\":\"{appId}\",\"name\":{h}}}");
            if (path == $"/v1/clients/{clientId}/roles") return Json($"{{\"items\":[{role}],\"nextCursor\":{h}}}");
            if (path == $"/v1/applications/{appId}/roles") return Json($"{{\"items\":[{role}],\"nextCursor\":{h}}}");
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        foreach (var path in new[] { $"/Clients/{clientId}/Roles?done=" + Uri.EscapeDataString(hostile), $"/Clients/{clientId}/Roles/Remove/{roleId}" })
        {
            var html = await b.GetStringAsync(path);
            Assert.DoesNotContain("<script>alert", html);
            Assert.DoesNotContain("<img src=x", html);
            Assert.Contains("&lt;script&gt;", html);
            Assert.DoesNotContain("class=\"notice\"", html);
        }
        var list = await b.GetStringAsync($"/Clients/{clientId}/Roles");
        Assert.DoesNotContain("<", Regex.Match(list, "href=\"(/Clients/[^\"]*cursor=[^\"]*)\"").Groups[1].Value);
        // the add page: the held list is empty (the stub holds the role, so it is excluded), the text still encoded
        var add = await b.GetStringAsync($"/Clients/{clientId}/Roles/Add?cursor=" + Uri.EscapeDataString(hostile));
        Assert.DoesNotContain("<script>alert", add);
    }

    [Theory]
    [InlineData("503", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("500", HttpStatusCode.BadGateway, "could not complete")]
    [InlineData("404", HttpStatusCode.NotFound, "")]
    public async Task Api_failures_get_an_honest_status_without_leaking_detail(string mode, HttpStatusCode expected, string text)
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (!armed || !r.RequestUri!.AbsolutePath.Contains("/roles")) return null;
            return mode switch
            {
                "503" => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                "404" => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") },
                _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{\"detail\":\"secret-internal\"}") },
            };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("failapp"));
        var client = await CreateClientAsync(api, Unique("fail"), app);
        var role = await CreateRoleAsync(api, app, "r");
        var tokenFrom = $"/Clients/Edit/{client}";
        armed = true;
        var responses = new List<HttpResponseMessage>
        {
            await b.GetAsync($"/Clients/{client}/Roles"),
            await b.GetAsync($"/Clients/{client}/Roles/Add"),
            await b.GetAsync($"/Clients/{client}/Roles/Remove/{role}"),
            await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = role.ToString() }, tokenFrom),
        };
        foreach (var r in responses)
        {
            var body = await r.Content.ReadAsStringAsync();
            Assert.Equal(expected, r.StatusCode);
            Assert.Contains(text, body);
            Assert.DoesNotContain("secret-internal", body);
        }
    }

    [Fact]
    public async Task A_conflict_from_the_api_is_shown_as_fixed_text_and_its_detail_is_not_echoed()
    {
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            r.Method == HttpMethod.Put && r.RequestUri!.AbsolutePath.Contains("/roles/")
                ? new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("{\"detail\":\"echo <b>secret-detail</b>\"}", System.Text.Encoding.UTF8, "application/json") }
                : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var app = await CreateAppAsync(api, Unique("conf"));
        var client = await CreateClientAsync(api, Unique("conf"), app);
        var role = await CreateRoleAsync(api, app, "r");
        var r = await WebFixture.PostFormAsync(b, $"/Clients/{client}/Roles/Add", new() { ["RoleId"] = role.ToString() }, $"/Clients/{client}/Roles/Add");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Equal("The role could not be changed because of a conflict.", Alert(html));
        Assert.DoesNotContain("secret-detail", html);
    }

    [Fact]
    public async Task A_client_of_the_reserved_application_is_offered_no_role_and_a_crafted_post_is_refused()
    {
        var gk = Guid.Empty; // the reserved application's id in the fixture started below
        var clientId = Guid.NewGuid();
        var puts = 0;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (r.Method == HttpMethod.Put && path.StartsWith($"/v1/clients/{clientId}/roles/")) { puts++; return new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("{\"detail\":\"Application 'gatekeeper' is reserved: its service identities cannot hold roles.\"}", System.Text.Encoding.UTF8, "application/json") }; }
            if (path == $"/v1/clients/{clientId}") return Json($"{{\"id\":\"{clientId}\",\"name\":\"legacy\",\"appId\":\"{gk}\",\"isActive\":true,\"createdAt\":\"2026-01-01T00:00:00Z\",\"updatedAt\":\"2026-01-01T00:00:00Z\"}}");
            if (path == $"/v1/clients/{clientId}/roles") return Json("{\"items\":[],\"nextCursor\":null}");
            return null;
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var apps = (await (await ApiAdminAsync(f)).GetFromJsonAsync<JsonElement>("/v1/applications?limit=200")).GetProperty("items").EnumerateArray().ToList();
        gk = apps.Single(a => a.GetProperty("name").GetString() == "gatekeeper").GetProperty("id").GetGuid();
        var list = await b.GetStringAsync($"/Clients/{clientId}/Roles");
        Assert.Contains("cannot hold roles", list);
        Assert.DoesNotContain("/Roles/Add", list);
        var add = await b.GetStringAsync($"/Clients/{clientId}/Roles/Add");
        Assert.DoesNotContain("name=\"RoleId\"", add);
        var r = await WebFixture.PostFormAsync(b, $"/Clients/{clientId}/Roles/Add", new() { ["RoleId"] = Guid.NewGuid().ToString() }, $"/Clients/{clientId}/Roles/Add");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal(ClientsReservedText, Alert(await r.Content.ReadAsStringAsync()));
        Assert.Equal(1, puts); // forwarded to the API, which refuses it
    }

    private const string ClientsReservedText = "Clients of the reserved application cannot hold roles.";

    [Fact]
    public async Task A_session_the_api_ended_gets_the_sign_in_page()
    {
        WebFixture? f = null;
        var armed = false;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            armed && r.RequestUri!.AbsolutePath.Contains("/roles") ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : null)));
        using var _ = f;
        var b = await f.SignedInAsync();
        var api = await ApiAdminAsync(f);
        var client = await CreateClientAsync(api, Unique("gone"), await CreateAppAsync(api, Unique("goneapp")));
        armed = true;
        var r = await b.GetAsync($"/Clients/{client}/Roles");
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
    }

    [Fact]
    public void ForLog_drops_control_line_separator_and_format_characters()
    {
        var clean = Pages.Users.UserAccess.ForLog("a\r\nb\u2028c\u2029d\u202Ee\u200Bf");
        Assert.Equal("abcdef", clean);
    }
}
