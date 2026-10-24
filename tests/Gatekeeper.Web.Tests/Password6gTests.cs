extern alias api;

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeeper.Web.Tests;

/// <summary>Slice 6g: /Account/Password.</summary>
public class Password6gTests
{
    private const string Password = "a plain user password";
    private const string Fresh = "a brand new password 1";

    private sealed class CaptureLog : ILoggerProvider, ILogger
    {
        public ConcurrentQueue<string> Lines { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue(formatter(state, exception) + " " + exception);
    }

    /// <summary>A fixture whose API calls pass through <paramref name="rule"/> first (null: pass on). Every PUT to the password route is counted.</summary>
    private static WebFixture With(Func<HttpRequestMessage, HttpResponseMessage?>? rule = null, CaptureLog? log = null, ConcurrentQueue<HttpRequestMessage>? seen = null)
    {
        WebFixture? f = null;
        f = new WebFixture(false, s =>
        {
            if (log is not null) s.AddSingleton<ILoggerProvider>(log);
            s.AddHttpClient<GatekeeperApi>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(f!.Api.Server.CreateHandler(), r =>
            {
                if (r.Method == HttpMethod.Put && r.RequestUri!.AbsolutePath == "/v1/me/password") seen?.Enqueue(r);
                return rule?.Invoke(r);
            }));
        });
        return f;
    }

    private static async Task<(string Name, Guid Id)> NewUserAsync(WebFixture f, string? kind = null)
    {
        var admin = f.Api.CreateClient();
        var login = await admin.PostAsJsonAsync("/v1/auth/login", new { username = WebFixture.AdminName, password = WebFixture.AdminPassword, application = "gatekeeper" });
        admin.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        var name = $"pw-{Guid.NewGuid():N}"[..16];
        var user = await (await admin.PostAsJsonAsync("/v1/users", new { username = name, email = $"{name}@example.com", displayName = "Some One", kind })).Content.ReadFromJsonAsync<JsonElement>();
        var id = user.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutAsJsonAsync($"/v1/users/{id}/password", new { password = Password })).StatusCode);
        return (name, id);
    }

    private static async Task<HttpClient> SignInAsync(WebFixture f, string name, string password = Password)
    {
        var b = f.Browser();
        var r = await WebFixture.PostFormAsync(b, "/Login", new() { ["Username"] = name, ["Password"] = password });
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        return b;
    }

    private static Task<HttpResponseMessage> Submit(HttpClient b, string current, string replacement, string? confirm = null) =>
        WebFixture.PostFormAsync(b, "/Account/Password", new() { ["Current"] = current, ["New"] = replacement, ["Confirm"] = confirm ?? replacement });

    private static string ErrorText(string html) => WebUtility.HtmlDecode(Regex.Match(html, "class=\"error\"[^>]*>([^<]*)").Groups[1].Value);

    private static async Task<bool> StillSignedIn(HttpClient b)
    {
        var r = await b.GetAsync("/Account");
        return r.StatusCode == HttpStatusCode.OK;
    }

    [Fact]
    public async Task The_account_page_links_to_the_form_and_the_form_is_a_plain_hardened_page()
    {
        using var f = new WebFixture();
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        Assert.Contains("href=\"/Account/Password\"", await b.GetStringAsync("/Account"));

        var r = await b.GetAsync("/Account/Password");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString());
        Assert.Contains("default-src 'none'", string.Join(' ', r.Headers.GetValues("Content-Security-Policy")));
        var html = await r.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("__RequestVerificationToken", html);
        Assert.Matches("name=\"Current\"[^>]*autocomplete=\"current-password\"", html);
        Assert.Matches("name=\"New\"[^>]*autocomplete=\"new-password\"", html);
        Assert.Matches("name=\"Confirm\"[^>]*autocomplete=\"new-password\"", html);
        Assert.Equal(3, Regex.Matches(html, "type=\"password\"").Count);
        Assert.DoesNotMatch("<input[^>]*type=\"password\"[^>]*value=", html);
    }

    [Fact]
    public async Task A_correct_change_redirects_keeps_this_session_and_ends_the_users_other_sessions()
    {
        using var f = new WebFixture();
        var (name, _) = await NewUserAsync(f);
        var mine = await SignInAsync(f, name);
        var elsewhere = await SignInAsync(f, name);

        var r = await Submit(mine, Password, Fresh);
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/Account?done=password", r.Headers.Location?.OriginalString);
        var page = await mine.GetStringAsync("/Account?done=password");
        Assert.Contains("Password changed. Your other sessions were ended; this one stays signed in.", page);
        Assert.True(await StillSignedIn(mine));
        Assert.Contains("(your current session)", page);
        // the other browser's API session is over: its next page ends it
        Assert.NotEqual(HttpStatusCode.OK, (await elsewhere.GetAsync("/Account")).StatusCode);

        var again = f.Browser();
        Assert.Equal(HttpStatusCode.OK, (await WebFixture.PostFormAsync(again, "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode); // login page again: old password refused
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(again, "/Login", new() { ["Username"] = name, ["Password"] = Fresh })).StatusCode);
    }

    [Fact]
    public async Task A_wrong_current_password_is_a_fixed_form_error_and_the_session_stays()
    {
        var log = new CaptureLog();
        using var f = With(log: log);
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        var r = await Submit(b, "WRONG-secret-current", Fresh);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Equal(Pages.Account.PasswordModel.WrongCurrentText, ErrorText(html));
        Assert.DoesNotContain("WRONG-secret-current", html);
        Assert.DoesNotContain(Fresh, html);
        Assert.DoesNotMatch("<input[^>]*type=\"password\"[^>]*value=", html);
        Assert.True(await StillSignedIn(b)); // not treated as an ended session
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode); // unchanged
        Assert.DoesNotContain("WRONG-secret-current", string.Join('\n', log.Lines));
        Assert.DoesNotContain(Fresh, string.Join('\n', log.Lines));
    }

    [Fact]
    public async Task Local_mistakes_never_reach_the_api()
    {
        var seen = new ConcurrentQueue<HttpRequestMessage>();
        using var f = With(seen: seen);
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        var cases = new[]
        {
            ((string?)"", Fresh, Fresh, Pages.Account.PasswordModel.MissingText),
            (Password, "", "", Pages.Account.PasswordModel.MissingText),
            (Password, Fresh, "something else entirely", Pages.Account.PasswordModel.MismatchText),
            (Password, Password, Password, Pages.Account.PasswordModel.SameText),
        };
        foreach (var (current, replacement, confirm, text) in cases)
        {
            var r = await Submit(b, current!, replacement, confirm);
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            var html = await r.Content.ReadAsStringAsync();
            Assert.Equal(text, ErrorText(html));
            Assert.DoesNotContain("something else entirely", html);
        }
        Assert.Empty(seen);
    }

    [Fact]
    public async Task A_new_password_the_api_refuses_gets_the_fixed_rules_text()
    {
        using var f = With();
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        var r = await Submit(b, Password, "tiny");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var html = await r.Content.ReadAsStringAsync();
        Assert.Equal(Pages.Users.UserAccess.PasswordRulesText, ErrorText(html));
        Assert.DoesNotContain("tiny", html);
    }

    [Fact]
    public async Task Throttling_and_other_api_answers_become_fixed_texts_and_the_session_stays()
    {
        var mode = "";
        var log = new CaptureLog();
        using var f = With(r => mode switch
        {
            "429" => new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new StringContent("{\"detail\":\"echo-SECRET-PW\"}") },
            "403" => new HttpResponseMessage(HttpStatusCode.Forbidden),
            "500" => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("SECRET-PW boom") },
            _ => null,
        }, log, null);
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        foreach (var (m, status) in new[] { ("429", HttpStatusCode.TooManyRequests), ("403", HttpStatusCode.Forbidden), ("500", HttpStatusCode.BadGateway) })
        {
            mode = m;
            var r = await Submit(b, Password, Fresh);
            Assert.Equal(status, r.StatusCode);
            var html = await r.Content.ReadAsStringAsync();
            Assert.DoesNotContain("SECRET-PW", html);
            Assert.DoesNotContain(Fresh, html);
            if (m == "429") Assert.Equal(Pages.Account.PasswordModel.ThrottledText, ErrorText(html));
        }
        mode = "";
        Assert.True(await StillSignedIn(b));
        Assert.DoesNotContain("SECRET-PW", string.Join('\n', log.Lines));
        Assert.DoesNotContain(Fresh, string.Join('\n', log.Lines));
        Assert.DoesNotContain(Password, string.Join('\n', log.Lines.Where(l => !l.Contains("/Login"))));
    }

    [Fact]
    public async Task A_401_from_the_api_ends_the_web_session_cleanly()
    {
        var mode = "";
        using var f = With(r => mode == "401" ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : null);
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        mode = "401";
        var r = await Submit(b, Password, Fresh);
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/Login?ended=1", r.Headers.Location?.OriginalString);
    }

    private sealed class Recording(List<HttpRequestMessage> seen) : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            seen.Add(request);
            if (request.Content is not null) Bodies.Add(await request.Content.ReadAsStringAsync(ct));
            return request.RequestUri!.AbsolutePath.EndsWith("/auth/login")
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"accessToken\":\"a.b.c\",\"expiresIn\":900,\"refreshToken\":\"gkr_x\",\"refreshExpiresIn\":3600}", System.Text.Encoding.UTF8, "application/json") }
                : new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    [Fact]
    public async Task The_request_carries_the_browsers_address_and_both_passwords_only_in_the_body()
    {
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow);
        var seen = new List<HttpRequestMessage>();
        var handler = new Recording(seen);
        var accessor = new Microsoft.AspNetCore.Http.HttpContextAccessor { HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext { Connection = { RemoteIpAddress = IPAddress.Parse("203.0.113.7") } } };
        var api = new GatekeeperApi(new HttpClient(handler) { BaseAddress = new Uri("http://api/") }, new WebSessions(time), time, accessor);
        var session = await api.LoginAsync("alice", "pw", CancellationToken.None);
        await api.ChangeOwnPasswordAsync(session, "CUR-secret-pw", "NEW-secret-pw", CancellationToken.None);
        var put = seen.Single(r => r.Method == HttpMethod.Put);
        Assert.Equal("/v1/me/password", put.RequestUri!.PathAndQuery); // no password in the URL
        Assert.Equal(["203.0.113.7"], put.Headers.GetValues("X-Forwarded-For"));
        Assert.DoesNotContain("secret", put.RequestUri.ToString() + put.Headers);
        Assert.Contains("CUR-secret-pw", handler.Bodies.Last());
    }

    [Fact]
    public async Task The_form_needs_antiforgery_and_a_signed_in_user_and_has_no_other_verbs()
    {
        using var f = new WebFixture();
        var (name, _) = await NewUserAsync(f);
        var b = await SignInAsync(f, name);
        var forged = await b.PostAsync("/Account/Password", new FormUrlEncodedContent(new Dictionary<string, string> { ["Current"] = Password, ["New"] = Fresh, ["Confirm"] = Fresh }));
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await f.Browser().GetAsync("/Account/Password")).StatusCode);
        Assert.Equal("/Login", (await f.Browser().GetAsync("/Account/Password")).Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, (await WebFixture.PostFormAsync(f.Browser(), "/Login", new() { ["Username"] = name, ["Password"] = Password })).StatusCode); // unchanged
    }

    [Fact]
    public async Task An_administrator_uses_the_same_page()
    {
        using var f = new WebFixture();
        var b = await f.SignedInAsync();
        Assert.Contains("/Account/Password", await b.GetStringAsync("/Account"));
        var r = await Submit(b, WebFixture.AdminPassword, "an admin new password 2");
        Assert.Equal("/Account?done=password", r.Headers.Location?.OriginalString);
        Assert.True(await StillSignedIn(b));
        Assert.Equal(HttpStatusCode.OK, (await b.GetAsync("/Applications")).StatusCode);
    }
}
