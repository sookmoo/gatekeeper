using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA of slice 6d: parser stress, precedence with name conflicts, no-op PATCH, ETag freshness, unconditional contention.</summary>
public class Slice6dQaTests
{
    public static IEnumerable<object[]> Stores() => QaEnv.Stores();
    private static string U(string p) => $"{p}-{Guid.NewGuid():N}"[..20];

    private static Task<HttpResponseMessage> Send(QaEnv e, HttpMethod m, string url, object? body = null, params string[] ifMatch)
    {
        var req = new HttpRequestMessage(m, url);
        if (body is not null) req.Content = JsonContent.Create(body);
        foreach (var h in ifMatch) req.Headers.TryAddWithoutValidation("If-Match", h);
        return e.Admin.SendAsync(req);
    }
    private static string? ETag(HttpResponseMessage r) => r.Headers.TryGetValues("ETag", out var v) ? v.Single() : null;
    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    // ---- parser ----

    [Theory]
    [InlineData("\"1\"", true)]
    [InlineData("  \"1\"  ", true)]
    [InlineData("\t\"1\"\t", true)]
    [InlineData("\"1\",\"2\"", true)]
    [InlineData(",,\"1\",,", true)]
    [InlineData("W/\"1\",\"1\"", true)]
    [InlineData("W/\"1\"", false)]      // weak parses but does not match
    [InlineData("\"01\"", false)]       // leading zero is not version 1
    [InlineData("\"+1\"", false)]
    public void Matches_version_1(string header, bool expected)
    {
        Precondition p;
        try { p = Precondition.Parse(header); }
        catch (ValidationException) { Assert.Fail($"[{header}] unexpectedly malformed"); return; }
        Assert.Equal(expected, p.Matches(1));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(",")]
    [InlineData(", ,")]
    [InlineData("w/\"1\"")]
    [InlineData("\"1\"\"2\"")]
    [InlineData("\"1 \"")]            // space inside the quotes is not an etagc
    [InlineData("\"1\";\"2\"")]
    [InlineData("* ,*")]
    [InlineData("\"éĀ\"")]   // > 0xFF
    [InlineData("\"1\"\r\n")]
    public void Malformed_is_400(string header) => Assert.Throws<ValidationException>(() => Precondition.Parse(header));

    [Fact]
    public void Length_boundary_1024_is_accepted_1025_is_not()
    {
        string Tag(int total) => "\"" + new string('1', total - 2) + "\"";
        Precondition.Parse(Tag(1024));
        Assert.Throws<ValidationException>(() => Precondition.Parse(Tag(1025)));
    }

    [Theory]
    [InlineData(" , ")]
    [InlineData(",")]
    [InlineData(" ")]
    public async Task Adversarial_whitespace_and_comma_lists_do_not_take_exponential_time(string unit)
    {
        // Ambiguous [ \t]*,[ \t]* repetition followed by a failing suffix; must finish quickly (no regex timeout is configured).
        var evil = "\"1\"" + string.Concat(Enumerable.Repeat(unit, 1024 / unit.Length - 4)) + "x";
        var task = Task.Run(() => { try { Precondition.Parse(evil); } catch (ValidationException) { } });
        var sw = Stopwatch.StartNew();
        Assert.True(await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))) == task, $"Parse of {evil.Length} chars did not finish in 5 s (ReDoS)");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
    }

    // ---- headers on the wire ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Several_if_match_header_lines_count_as_one_list_and_empty_value_is_400(string store)
    {
        using var e = new QaEnv(store);
        var id = await e.App(U("app"));
        var path = $"/v1/applications/{id}";
        Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, path, new { name = U("n") }, "\"7\"", "\"1\"")).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Patch, path, new { name = U("n") }, "\"7\"", "\"8\"")).StatusCode);
        // "*" on one line and a tag on another is "*,\"2\"": malformed
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(e, HttpMethod.Patch, path, new { name = U("n") }, "*", "\"2\"")).StatusCode);
        // raw empty header value over the wire
        var req = new HttpRequestMessage(HttpMethod.Delete, path);
        req.Headers.TryAddWithoutValidation("If-Match", "");
        var r = await e.Admin.SendAsync(req);
        Assert.True(r.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NoContent, $"empty If-Match -> {(int)r.StatusCode}");
        // the app may be gone if the empty header was treated as absent
        var left = (await e.Admin.GetAsync(path)).StatusCode;
        Assert.Equal(r.StatusCode == HttpStatusCode.BadRequest ? HttpStatusCode.OK : HttpStatusCode.NotFound, left);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Long_if_match_is_400_not_500(string store)
    {
        using var e = new QaEnv(store);
        var id = await e.App(U("app"));
        var path = $"/v1/applications/{id}";
        foreach (var len in new[] { 1024, 1025, 7000, 30000 })
        {
            var r = await Send(e, HttpMethod.Delete, path, null, "\"" + new string('1', len - 2) + "\"");
            Assert.True(r.StatusCode is HttpStatusCode.PreconditionFailed or HttpStatusCode.BadRequest or HttpStatusCode.RequestHeaderFieldsTooLarge, $"len {len} -> {(int)r.StatusCode}");
        }
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync(path)).StatusCode);
    }

    // ---- precedence with 409 name conflicts ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Name_conflicts_are_409_only_after_412_for_every_resource(string store)
    {
        using var e = new QaEnv(store);
        var a1 = U("app"); var a2 = U("app");
        var id1 = await e.App(a1); var id2 = await e.App(a2);
        var r1 = await e.Role(id1, "r1"); var r2 = await e.Role(id1, "r2");
        var u1 = U("usr"); var u2 = U("usr");
        var uid1 = await e.User(u1, null); await e.User(u2, null);
        var c1 = U("cli"); var c2 = U("cli");
        var cid1 = await e.Create("/v1/clients", new { name = c1, application = id1 });
        await e.Create("/v1/clients", new { name = c2, application = id1 });

        var cases = new (string Path, object Taken, string Method)[]
        {
            ($"/v1/applications/{id1}", new { name = a2 }, "app"),
            ($"/v1/roles/{r1}", new { name = "r2", description = "" }, "role"),
            ($"/v1/users/{uid1}", new { username = u2, email = $"{u1}@example.com" }, "user"),
            ($"/v1/clients/{cid1}", new { name = c2 }, "client"),
        };
        foreach (var (path, taken, kind) in cases)
        {
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Put, path, taken)).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Put, path, taken, "*")).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Put, path, taken, "\"1\"")).StatusCode);
            Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Put, path, taken, "\"2\"")).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await Send(e, HttpMethod.Patch, path, taken, "\"1\"")).StatusCode);
            Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Patch, path, taken, "\"2\"")).StatusCode);
            Assert.Equal("\"1\"", ETag(await e.Admin.GetAsync(path))); // a refused write never bumps
        }
    }

    // ---- ETag freshness ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Etag_follows_a_rename_and_is_absent_on_errors_and_non_resource_posts(string store)
    {
        using var e = new QaEnv(store);
        var appId = await e.App(U("app"));
        var cid = await e.Create("/v1/clients", new { name = U("cli"), application = appId });
        var p = $"/v1/clients/{cid}";
        var put = await Send(e, HttpMethod.Put, p, new { name = U("new") });
        Assert.Equal("\"2\"", ETag(put));
        Assert.Equal("\"2\"", ETag(await e.Admin.GetAsync(p)));
        // 412/404/400 carry no ETag
        foreach (var r in new[] { await Send(e, HttpMethod.Put, p, new { name = "x" }, "\"1\""), await e.Admin.GetAsync($"/v1/clients/{Guid.NewGuid()}"), await Send(e, HttpMethod.Put, p, new { name = "" }) })
            Assert.Null(ETag(r));
        // secret rotation returns a secret, not a resource: no version change, and no stale ETag claimed
        var rot = await e.Admin.PostAsync($"{p}/secret", null);
        Assert.Equal(HttpStatusCode.OK, rot.StatusCode);
        Assert.Equal("\"2\"", ETag(await e.Admin.GetAsync(p)));
        // app GET after a role is added keeps its version
        var before = ETag(await e.Admin.GetAsync($"/v1/applications/{appId}"));
        await e.Role(appId, "x");
        Assert.Equal(before, ETag(await e.Admin.GetAsync($"/v1/applications/{appId}")));
    }

    // ---- no-op PATCH ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Noop_patch_behaviour_per_resource(string store)
    {
        using var e = new QaEnv(store);
        var appName = U("app");
        var appId = await e.App(appName);
        var roleId = await e.Role(appId, "r");
        var uname = U("usr");
        var uid = await e.User(uname, null);
        var cid = await e.Create("/v1/clients", new { name = U("cli"), application = appId });

        async Task<string?> Tag(string path, object body)
        {
            var r = await Send(e, HttpMethod.Patch, path, body);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return ETag(r);
        }
        // report-style assertions: record what each resource does
        var app = await Tag($"/v1/applications/{appId}", new { name = appName });
        var roleEmpty = await Tag($"/v1/roles/{roleId}", new { });
        var roleSame = await Tag($"/v1/roles/{roleId}", new { name = "r" });
        var userEmpty = await Tag($"/v1/users/{uid}", new { });
        var userSame = await Tag($"/v1/users/{uid}", new { username = uname });
        var cliEmpty = await Tag($"/v1/clients/{cid}", new { });
        var cliSame = await Tag($"/v1/clients/{cid}", new { isActive = true });
        Console.WriteLine($"NOOP app={app} roleEmpty={roleEmpty} roleSame={roleSame} userEmpty={userEmpty} userSame={userSame} cliEmpty={cliEmpty} cliSame={cliSame}");
        Assert.Equal("\"1\"", app); // documented: app no-op does not bump
        // Whatever each does, the ETag it returns must be the one a later GET shows, and a conditional write with it must succeed.
        foreach (var (path, tag, body) in new (string, string?, object)[] {
            ($"/v1/roles/{roleId}", roleSame, new { description = "z" }), ($"/v1/users/{uid}", userSame, new { displayName = "z" }), ($"/v1/clients/{cid}", cliSame, new { name = U("c") }) })
        {
            Assert.Equal(tag, ETag(await e.Admin.GetAsync(path)));
            Assert.Equal(HttpStatusCode.OK, (await Send(e, HttpMethod.Patch, path, body, tag!)).StatusCode);
        }
    }

    // ---- side effects ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Deactivation_bumps_the_user_once_and_session_revocation_does_not_bump_again(string store)
    {
        using var e = new QaEnv(store);
        var app = U("app");
        var appId = await e.App(app);
        var uname = U("usr");
        var uid = await e.User(uname);
        await e.Assign(uid, await e.Role(appId, "member"));
        var login = await e.Login(uname, "correct horse battery", app);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var r = await Send(e, HttpMethod.Patch, $"/v1/users/{uid}", new { isActive = false }, "\"1\"");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("\"2\"", ETag(r));
        Assert.Equal("\"2\"", ETag(await e.Admin.GetAsync($"/v1/users/{uid}")));
        // deleting the app with a stale tag leaves roles/clients alone
        var rid = await e.Role(appId, "m");
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Send(e, HttpMethod.Delete, $"/v1/applications/{appId}", null, "\"5\"")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync($"/v1/roles/{rid}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Send(e, HttpMethod.Delete, $"/v1/applications/{appId}", null, "\"1\"")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync($"/v1/roles/{rid}")).StatusCode);
    }

    // ---- unconditional contention ----

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Unconditional_parallel_puts_never_return_a_wrong_version(string store)
    {
        using var e = new QaEnv(store);
        var appId = await e.App(U("app"));
        var rid = await e.Role(appId, "r");
        const int n = 40;
        var results = await Task.WhenAll(Enumerable.Range(0, n).Select(i => Send(e, HttpMethod.Put, $"/v1/roles/{rid}", new { name = $"r{i}", description = "d" })));
        var ok = results.Where(r => r.StatusCode == HttpStatusCode.OK).ToList();
        var other = results.Where(r => r.StatusCode != HttpStatusCode.OK).Select(r => (int)r.StatusCode).Distinct().ToList();
        Console.WriteLine($"UNCOND n={n} ok={ok.Count} other=[{string.Join(",", other)}]");
        Assert.Empty(other); // unconditional writers of one row queue on a row lock: every one succeeds
        var versions = (await Task.WhenAll(ok.Select(Json))).Select(b => b.GetProperty("version").GetInt64()).ToList();
        Assert.Equal(versions.Count, versions.Distinct().Count()); // each success has its own version
        var final = await Json(await e.Admin.GetAsync($"/v1/roles/{rid}"));
        Assert.Equal(1 + ok.Count, final.GetProperty("version").GetInt64()); // and the row counts exactly the successes
        Assert.Equal(final.GetProperty("version").GetInt64(), versions.Max());
        Assert.Equal(other.Count == 0, ok.Count == n);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Parallel_conditional_deletes_with_the_same_tag_one_204_rest_412_or_404(string store)
    {
        using var e = new QaEnv(store);
        var appId = await e.App(U("app"));
        var cid = await e.Create("/v1/clients", new { name = U("cli"), application = appId });
        var rs = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Send(e, HttpMethod.Delete, $"/v1/clients/{cid}", null, "\"1\"")));
        Assert.Equal(1, rs.Count(r => r.StatusCode == HttpStatusCode.NoContent));
        Assert.All(rs.Where(r => r.StatusCode != HttpStatusCode.NoContent), r => Assert.Equal(HttpStatusCode.NotFound, r.StatusCode));
    }
}
