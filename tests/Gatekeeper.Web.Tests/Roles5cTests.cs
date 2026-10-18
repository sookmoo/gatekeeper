extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

public class Roles5cTests : IClassFixture<WebFixture>
{
    private readonly WebFixture _f;

    public Roles5cTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static async Task<string> CreateAppAsync(HttpClient b, string name)
    {
        var r = await WebFixture.PostFormAsync(b, "/Applications/Create", new() { ["Name"] = name });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var list = await b.GetStringAsync("/Applications");
        return Regex.Match(list, $"<td>{name}</td>\\s*<td><code>([0-9a-f-]{{36}})</code>").Groups[1].Value;
    }

    private static async Task<string> ReservedIdAsync(HttpClient b) =>
        Regex.Match(await b.GetStringAsync("/Applications"), "<td>gatekeeper</td>\\s*<td><code>([0-9a-f-]{36})</code>").Groups[1].Value;

    private static string RoleId(string html, string name) =>
        Regex.Match(html, $"<td>{Regex.Escape(name)}</td>\\s*<td>[^<]*</td>\\s*<td>\\s*<a href=\"/Applications/[0-9a-f-]{{36}}/Roles/Edit/([0-9a-f-]{{36}})\"").Groups[1].Value;

    private async Task<HttpClient> ApiAdminAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return c;
    }

    [Fact]
    public async Task Role_pages_need_a_session_and_post_needs_the_antiforgery_token()
    {
        var b = _f.Browser();
        var (a, r) = (Guid.NewGuid(), Guid.NewGuid());
        foreach (var path in new[] { $"/Applications/{a}/Roles", $"/Applications/{a}/Roles/Create", $"/Applications/{a}/Roles/Edit/{r}", $"/Applications/{a}/Roles/Delete/{r}" })
        {
            var resp = await b.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.Equal("/Login", resp.Headers.Location?.OriginalString);
        }

        var s = await _f.SignedInAsync();
        var app = await CreateAppAsync(s, Unique("csrf"));
        var empty = new FormUrlEncodedContent(new Dictionary<string, string> { ["Name"] = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Applications/{app}/Roles/Create", empty)).StatusCode);
        await WebFixture.PostFormAsync(s, $"/Applications/{app}/Roles/Create", new() { ["Name"] = "keep" });
        var id = RoleId(await s.GetStringAsync($"/Applications/{app}/Roles"), "keep");
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Applications/{app}/Roles/Edit/{id}", empty)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.PostAsync($"/Applications/{app}/Roles/Delete/{id}", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
        Assert.Contains("keep", await s.GetStringAsync($"/Applications/{app}/Roles"));
    }

    [Fact]
    public async Task Roles_can_be_created_renamed_redescribed_and_deleted_with_confirmation()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("rapp"));
        var path = $"/Applications/{app}/Roles";
        Assert.Contains("No roles.", await b.GetStringAsync(path));

        var created = await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "editor", ["Description"] = "can edit" });
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.Equal($"{path}?done=created", created.Headers.Location?.OriginalString);
        var list = await b.GetStringAsync($"{path}?done=created");
        Assert.Contains("Role created.", list);
        Assert.Contains("can edit", list);
        var id = RoleId(list, "editor");
        Assert.NotEmpty(id);

        var dup = await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "editor" });
        Assert.Equal(HttpStatusCode.OK, dup.StatusCode);
        var dupHtml = await dup.Content.ReadAsStringAsync();
        Assert.Contains("role=\"alert\"", dupHtml);
        Assert.Contains("already", dupHtml, StringComparison.OrdinalIgnoreCase); // the API's 409 text

        var form = await b.GetStringAsync($"{path}/Edit/{id}");
        Assert.Contains("value=\"editor\"", form);
        Assert.Contains("value=\"can edit\"", form);
        var saved = await WebFixture.PostFormAsync(b, $"{path}/Edit/{id}", new() { ["Name"] = "writer", ["Description"] = "can write" });
        Assert.Equal($"{path}?done=updated", saved.Headers.Location?.OriginalString);
        list = await b.GetStringAsync(path);
        Assert.Contains("<td>writer</td>", list);
        Assert.Contains("can write", list);
        Assert.DoesNotContain("<td>editor</td>", list);

        var tooLong = await WebFixture.PostFormAsync(b, $"{path}/Edit/{id}", new() { ["Name"] = "writer", ["Description"] = new string('d', 300) });
        Assert.Equal(HttpStatusCode.OK, tooLong.StatusCode);
        Assert.Contains("role=\"alert\"", await tooLong.Content.ReadAsStringAsync());

        var confirm = await b.GetStringAsync($"{path}/Delete/{id}");
        Assert.Contains("<strong>writer</strong>", confirm);
        Assert.Contains("<td>writer</td>", await b.GetStringAsync(path)); // viewing the confirmation deletes nothing
        var deleted = await WebFixture.PostFormAsync(b, $"{path}/Delete/{id}", new());
        Assert.Equal($"{path}?done=deleted", deleted.Headers.Location?.OriginalString);
        Assert.DoesNotContain("<td>writer</td>", await b.GetStringAsync(path));
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"{path}/Edit/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"{path}/Delete/{id}")).StatusCode);
    }

    [Fact]
    public async Task Unknown_app_or_role_gives_the_404_page_and_a_role_of_another_app_is_not_reachable()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("a404"));
        var other = await CreateAppAsync(b, Unique("o404"));
        await WebFixture.PostFormAsync(b, $"/Applications/{app}/Roles/Create", new() { ["Name"] = "r1" });
        var id = RoleId(await b.GetStringAsync($"/Applications/{app}/Roles"), "r1");
        var ghost = Guid.NewGuid();

        foreach (var path in new[] { $"/Applications/{ghost}/Roles", $"/Applications/{ghost}/Roles/Create", $"/Applications/{app}/Roles/Edit/{ghost}", $"/Applications/{app}/Roles/Delete/{ghost}", $"/Applications/{other}/Roles/Edit/{id}", $"/Applications/{other}/Roles/Delete/{id}" })
            Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(path)).StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Applications/{ghost}/Roles/Create", new() { ["Name"] = "x" }, tokenFrom: $"/Applications/{app}/Roles/Create")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await WebFixture.PostFormAsync(b, $"/Applications/{other}/Roles/Delete/{id}", new(), tokenFrom: $"/Applications/{app}/Roles/Delete/{id}")).StatusCode);
        Assert.Contains("<td>r1</td>", await b.GetStringAsync($"/Applications/{app}/Roles")); // still there
    }

    [Fact]
    public async Task Names_and_descriptions_are_html_encoded()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("enc"));
        var path = $"/Applications/{app}/Roles";
        // The API restricts role names, so hostile text can only arrive in the description; it must be encoded where it is shown.
        var hostile = "<script>alert(1)</script><img src=x onerror=1>\"'";
        await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "plain", ["Description"] = hostile });
        var id = RoleId(await b.GetStringAsync(path), "plain");
        var api = await ApiAdminAsync();
        var patched = await api.PatchAsJsonAsync($"/v1/roles/{id}", new { description = hostile });
        Assert.True(patched.IsSuccessStatusCode || patched.StatusCode == HttpStatusCode.BadRequest);

        foreach (var url in new[] { path, $"{path}/Edit/{id}", $"{path}/Delete/{id}" })
        {
            var html = await b.GetStringAsync(url);
            Assert.DoesNotContain("<script>alert", html);
            Assert.DoesNotContain("<img src=x", html);
        }

        // hostile text sent back through a failing form is encoded too
        var r = await WebFixture.PostFormAsync(b, path + "/Create", new() { ["Name"] = "<script>alert(2)</script>", ["Description"] = hostile });
        var body = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>alert", body);
        Assert.DoesNotContain("<img src=x", body);
    }

    [Fact]
    public async Task The_reserved_application_shows_its_roles_read_only_and_refuses_changes()
    {
        var b = await _f.SignedInAsync();
        var gk = await ReservedIdAsync(b);
        var path = $"/Applications/{gk}/Roles";
        var list = await b.GetStringAsync(path);
        Assert.Contains("<td>admin</td>", list);
        Assert.Contains("read-only", list);
        Assert.DoesNotContain("/Roles/Create", list);
        Assert.DoesNotContain("/Roles/Edit/", list);
        Assert.DoesNotContain("/Roles/Delete/", list);
        Assert.Contains($"href=\"/Applications/{gk}/Roles\"", await b.GetStringAsync("/Applications"));

        var adminRole = (await (await ApiAdminAsync()).GetFromJsonAsync<JsonElement>($"/v1/applications/{gk}/roles")).GetProperty("items")[0].GetProperty("id").GetString();
        var create = await b.GetStringAsync(path + "/Create");
        Assert.DoesNotContain("<form", create.Replace("<form method=\"post\" action=\"/Logout\"", "")[create.IndexOf("<main", StringComparison.Ordinal)..]);

        // crafted posts (token taken from another page) are refused and change nothing
        var token = await WebFixture.TokenAsync(b, "/Applications");
        foreach (var (url, fields) in new[]
        {
            (path + "/Create", new Dictionary<string, string> { ["Name"] = "intruder" }),
            ($"{path}/Edit/{adminRole}", new Dictionary<string, string> { ["Name"] = "renamed" }),
            ($"{path}/Delete/{adminRole}", new Dictionary<string, string>()),
        })
        {
            fields["__RequestVerificationToken"] = token;
            var r = await b.PostAsync(url, new FormUrlEncodedContent(fields));
            Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
            Assert.Contains("role=\"alert\"", await r.Content.ReadAsStringAsync());
        }

        // a crafted Edit that only changes the description is refused too
        var edit = await b.PostAsync($"{path}/Edit/{adminRole}", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["Name"] = "admin", ["Description"] = "tampered", ["__RequestVerificationToken"] = token }));
        Assert.Equal(HttpStatusCode.Conflict, edit.StatusCode);
        var after = await (await ApiAdminAsync()).GetFromJsonAsync<JsonElement>($"/v1/roles/{adminRole}");
        Assert.Equal("Manages Gatekeeper", after.GetProperty("description").GetString());
        list = await b.GetStringAsync(path);
        Assert.Contains("<td>admin</td>", list);
        Assert.DoesNotContain("intruder", list);
        Assert.DoesNotContain("renamed", list);

        // the refused attempt reached the API, so the audit trail records it under the signed-in administrator
        var users = _f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();
        var admin = (await users.ListAsync(username: WebFixture.AdminName, slice: new Gatekeeper.Application.Slice(0, 1))).Single();
        var audit = await (await ApiAdminAsync()).GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("POST /v1/applications/{id}/roles") + "&limit=200");
        var attempt = JsonDocument.Parse(audit).RootElement.GetProperty("items").EnumerateArray()
            .Single(e => (e.GetProperty("target").GetString() ?? "").Contains(gk));
        Assert.Equal(admin.Id.ToString(), attempt.GetProperty("actor").GetString());
    }

    [Theory]
    [InlineData("503", HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData("down", HttpStatusCode.ServiceUnavailable, "Cannot reach")]
    [InlineData("500", HttpStatusCode.BadGateway, "reported an error")]
    public async Task Api_outages_on_the_role_pages_get_an_honest_status_without_leaking_detail(string mode, HttpStatusCode expected, string text)
    {
        var armed = false;
        WebFixture? f = null;
        f = new WebFixture(false, s => s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
        {
            if (!armed || !r.RequestUri!.AbsolutePath.EndsWith("/roles")) return null;
            return mode switch
            {
                "503" => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                "down" => throw new HttpRequestException("refused at 10.1.2.3"),
                _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{\"detail\":\"secret-internal\"}") },
            };
        })));
        using var _ = f;
        var b = await f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("out"));
        armed = true;
        foreach (var r in new[] { await b.GetAsync($"/Applications/{app}/Roles"), await WebFixture.PostFormAsync(b, $"/Applications/{app}/Roles/Create", new() { ["Name"] = "x" }) })
        {
            var body = await r.Content.ReadAsStringAsync();
            Assert.Equal(expected, r.StatusCode);
            Assert.Contains(text, body);
            Assert.DoesNotContain("secret-internal", body);
            Assert.DoesNotContain("10.1.2.3", body);
        }
    }

    [Fact]
    public async Task Changes_are_audited_under_the_signed_in_admin()
    {
        var b = await _f.SignedInAsync();
        var app = await CreateAppAsync(b, Unique("aud"));
        await WebFixture.PostFormAsync(b, $"/Applications/{app}/Roles/Create", new() { ["Name"] = "audited" });
        var api = await ApiAdminAsync();
        var audit = await api.GetStringAsync("/v1/audit?action=" + Uri.EscapeDataString("POST /v1/applications/{id}/roles") + "&limit=200");
        var events = JsonDocument.Parse(audit).RootElement.GetProperty("items").EnumerateArray()
            .Where(e => (e.GetProperty("target").GetString() ?? "").Contains(app)).ToList();
        var e = Assert.Single(events);
        var users = _f.Api.Services.GetRequiredService<Gatekeeper.Application.IUserRepository>();
        var admin = (await users.ListAsync(username: WebFixture.AdminName, slice: new Gatekeeper.Application.Slice(0, 1))).Single();
        Assert.Equal(admin.Id.ToString(), e.GetProperty("actor").GetString()); // the audit names the real administrator, by id
    }
}
