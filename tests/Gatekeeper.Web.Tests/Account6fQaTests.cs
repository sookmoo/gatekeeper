extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 6f: non-administrators sign in and see /Account only.</summary>
public class Account6fQaTests : IClassFixture<WebFixture>
{
    private const string Password = "a plain user password";
    private readonly WebFixture _f;

    public Account6fQaTests(WebFixture f) => _f = f;

    private static string Unique(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private async Task<HttpClient> ApiAdminAsync()
    {
        var c = _f.Api.CreateClient();
        var r = await c.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        c.DefaultRequestHeaders.Authorization = new("Bearer", (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!);
        return c;
    }

    private async Task<(string Name, Guid Id)> NewUserAsync(string? kind = null)
    {
        using var admin = await ApiAdminAsync();
        var name = Unique("plain");
        var user = await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Plain <b>Person</b>", kind })).Content.ReadFromJsonAsync<JsonElement>();
        var id = user.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private async Task<HttpClient> SignInAsync(string name, string password = Password)
    {
        var b = _f.Browser();
        var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = password });
        Assert.True(r.StatusCode == HttpStatusCode.Redirect, "sign-in answered " + (int)r.StatusCode);
        Assert.Equal("/Account", r.Headers.Location?.OriginalString);
        return b;
    }

    private static List<Guid> SessionIds(string html) => Regex.Matches(html, "/Account/Sessions/Revoke/([0-9a-f-]{36})").Select(m => Guid.Parse(m.Groups[1].Value)).ToList();

    [Fact]
    public async Task A_non_administrator_signs_out_and_the_account_page_then_needs_a_sign_in_again()
    {
        var u = await NewUserAsync();
        var b = await SignInAsync(u.Name);
        var r = await WebFixture.PostFormAsync(b, "/Logout", new(), "/Account");
        Assert.True(r.StatusCode == HttpStatusCode.Redirect, "logout " + (int)r.StatusCode);
        var after = await b.GetAsync("/Account");
        Assert.Equal(HttpStatusCode.Redirect, after.StatusCode);
        Assert.Contains("/Login", after.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, (await b.GetAsync("/Users")).StatusCode); // not 403 once signed out
    }

    [Fact]
    public async Task A_shared_account_and_a_wrong_password_show_the_same_login_page_text()
    {
        var shared = await NewUserAsync("shared");
        var plain = await NewUserAsync();
        var a = await WebFixture.PostFormAsync(_f.Browser(), "/Login", new() { ["Username"] = shared.Name, ["Password"] = Password });
        var c = await WebFixture.PostFormAsync(_f.Browser(), "/Login", new() { ["Username"] = plain.Name, ["Password"] = "wrong wrong wrong" });
        Assert.Equal(a.StatusCode, c.StatusCode);
        Assert.Contains("Invalid credentials.", await a.Content.ReadAsStringAsync());
        Assert.DoesNotContain("administrator", (await a.Content.ReadAsStringAsync()).Replace("Administrators", ""), StringComparison.OrdinalIgnoreCase);
    }
}
