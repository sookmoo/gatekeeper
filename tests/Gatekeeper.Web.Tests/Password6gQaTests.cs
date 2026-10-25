extern alias api;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Gatekeeper.Web.Tests;

/// <summary>Independent QA of /Account/Password (slice 6g).</summary>
public class Password6gQaTests
{
    private const string Password = "a plain user password";
    private const string Fresh = "a brand new password 1";

    private static async Task<string> NewUserAsync(WebFixture f)
    {
        var admin = f.Api.CreateClient();
        var login = await admin.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        admin.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        var name = $"qa-{Guid.NewGuid():N}"[..16];
        var user = await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One" })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{user.GetProperty("id").GetGuid()}/password", new { password = Password })).StatusCode);
        return name;
    }

    private static async Task<HttpClient> SignInAsync(WebFixture f, string name)
    {
        var b = f.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
        return b;
    }

    private static Task<HttpResponseMessage> Submit(HttpClient b, string? cur, string? neu, string? confirm) =>
        WebFixture.PostFormAsync(b, "/Account/Password", new() { ["Current"] = cur ?? "", ["New"] = neu ?? "", ["Confirm"] = confirm ?? "" });

    [Fact]
    public async Task No_error_path_echoes_any_of_the_three_values_back()
    {
        using var f = new WebFixture();
        var b = await SignInAsync(f, await NewUserAsync(f));
        var cases = new (string?, string?, string?)[]
        {
            ("CURRENT-leak-1", "", ""), ("", "NEW-leak-2 xxxxxxx", "NEW-leak-2 xxxxxxx"),
            ("CURRENT-leak-1", "NEW-leak-2 xxxxxxx", "CONFIRM-leak-3 xx"),
            ("CURRENT-leak-1", "CURRENT-leak-1", "CURRENT-leak-1"),
            ("CURRENT-leak-1", "short", "short"),
            ("CURRENT-leak-1", "NEW-leak-2 xxxxxxx", "NEW-leak-2 xxxxxxx"),
        };
        foreach (var (c, n, k) in cases)
        {
            var html = await (await Submit(b, c, n, k)).Content.ReadAsStringAsync();
            Assert.DoesNotContain("leak", html);
            Assert.DoesNotMatch("<input[^>]*type=\"password\"[^>]*value=", html);
        }
    }

    [Fact]
    public async Task Overlong_input_is_a_fixed_text_not_a_500_and_changes_nothing()
    {
        using var f = new WebFixture();
        var name = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        var r = await Submit(b, Password, new string('n', 500), new string('n', 500));
        Assert.True((int)r.StatusCode is >= 400 and < 500, r.StatusCode.ToString());
        var r2 = await Submit(b, new string('c', 500), Fresh, Fresh);
        Assert.True((int)r2.StatusCode is >= 400 and < 500, r2.StatusCode.ToString());
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
    }

    [Fact]
    public async Task Five_wrong_attempts_through_the_web_then_a_fixed_throttle_page_and_the_session_stays()
    {
        using var f = new WebFixture();
        var name = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.BadRequest, (await Submit(b, $"wrong password {i} xx", Fresh, Fresh)).StatusCode);
        var r = await Submit(b, Password, Fresh, Fresh);
        Assert.Equal(HttpStatusCode.TooManyRequests, r.StatusCode);
        Assert.Contains(Pages.Account.PasswordModel.ThrottledText, WebUtility.HtmlDecode(await r.Content.ReadAsStringAsync()));
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Account")).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode);
    }

    [Theory]
    [InlineData("/Account?done=<script>alert(1)</script>")]
    [InlineData("/Account?done=nonsense")]
    public async Task A_crafted_done_value_shows_no_message_and_reflects_nothing(string url)
    {
        using var f = new WebFixture();
        var b = await SignInAsync(f, await NewUserAsync(f));
        var html = await b.GetStringAsync(url);
        Assert.DoesNotContain("alert(1)", html);
        Assert.DoesNotContain("nonsense", html);
        Assert.DoesNotContain("Password changed", html);
    }
}
