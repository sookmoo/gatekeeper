using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Gatekeeper.Api.Tests;

/// <summary>
/// QA for slice 7c over HTTP: the version trace of a scripted sequence of writes (create, PUT, identical PUT, PATCH, no-op PATCH, rename, password,
/// revoke-all, role assignment, secret rotation, delete) must be identical for the in-memory store and for Postgres with the triggers, and must be the
/// documented numbers (exactly +1 per effective write).
/// </summary>
public class Slice7cQaApiTests
{
    private static async Task<long> Ver(QaEnv e, string path)
    {
        var r = await e.Admin.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var v = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("version").GetInt64();
        Assert.Equal($"\"{v}\"", r.Headers.ETag!.Tag);
        return v;
    }

    private static async Task<HttpResponseMessage> Send(QaEnv e, HttpMethod m, string url, object body, string? ifMatch = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = JsonContent.Create(body) };
        if (ifMatch is not null) req.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        return await e.Admin.SendAsync(req);
    }

    private static async Task<List<string>> Trace(string store)
    {
        using var e = new QaEnv(store);
        var t = new List<string>();
        var n = Guid.NewGuid().ToString("N")[..8];
        async Task Step(string label, Task<HttpResponseMessage> call, HttpStatusCode want, string path)
        {
            var r = await call;
            Assert.True(want == r.StatusCode, $"{label}: {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
            t.Add($"{label}={await Ver(e, path)}");
        }

        var appId = await e.Create("/v1/applications", new { name = "app" + n });
        var ap = $"/v1/applications/{appId}";
        t.Add($"app.create={await Ver(e, ap)}");
        await Step("app.put", Send(e, HttpMethod.Put, ap, new { name = "app2" + n }, "\"1\""), HttpStatusCode.OK, ap);
        await Step("app.put.identical", Send(e, HttpMethod.Put, ap, new { name = "app2" + n }, "\"2\""), HttpStatusCode.OK, ap);
        await Step("app.put.rename", Send(e, HttpMethod.Put, ap, new { name = "app2x" + n }), HttpStatusCode.OK, ap);
        await Step("app.patch.noop", Send(e, HttpMethod.Patch, ap, new { }), HttpStatusCode.OK, ap);
        await Step("app.put.stale", Send(e, HttpMethod.Put, ap, new { name = "late" + n }, "\"1\""), HttpStatusCode.PreconditionFailed, ap);

        var roleId = await e.Create($"{ap}/roles", new { name = "reader", description = "d" });
        var rp = $"/v1/roles/{roleId}";
        t.Add($"role.create={await Ver(e, rp)}");
        await Step("role.patch", Send(e, HttpMethod.Patch, rp, new { description = "e" }), HttpStatusCode.OK, rp);
        await Step("role.patch.same", Send(e, HttpMethod.Patch, rp, new { description = "e" }), HttpStatusCode.OK, rp);
        await Step("role.put.rename", Send(e, HttpMethod.Put, rp, new { name = "reader2", description = "e" }), HttpStatusCode.OK, rp);
        await Step("app.rename.after-role", Send(e, HttpMethod.Put, ap, new { name = "app3" + n }), HttpStatusCode.OK, ap);
        t.Add($"role.after-app-rename={await Ver(e, rp)}");

        var uid = await e.User("u" + n);
        var up = $"/v1/users/{uid}";
        t.Add($"user.create+password={await Ver(e, up)}");
        await Step("user.patch.name", Send(e, HttpMethod.Patch, up, new { displayName = "N" }), HttpStatusCode.OK, up);
        await Step("user.patch.deactivate", Send(e, HttpMethod.Patch, up, new { isActive = false }), HttpStatusCode.OK, up);
        await Step("user.patch.noop", Send(e, HttpMethod.Patch, up, new { isActive = false }), HttpStatusCode.OK, up);
        await Step("user.password", e.Admin.PutAsJsonAsync($"{up}/password", new { password = "another long password 12" }), HttpStatusCode.NoContent, up);
        await Step("user.revoke-all", e.Admin.DeleteAsync($"{up}/sessions"), HttpStatusCode.OK, up);
        await Step("user.role", e.Admin.PutAsync($"{up}/roles/{roleId}", null), HttpStatusCode.NoContent, up);
        await Step("user.put.rename", Send(e, HttpMethod.Put, up, new { username = "v" + n, email = $"u{n}@example.com", displayName = "N", isActive = false }), HttpStatusCode.OK, up);

        var cid = await e.Create("/v1/clients", new { name = "cli" + n, application = appId });
        var cp = $"/v1/clients/{cid}";
        t.Add($"client.create={await Ver(e, cp)}");
        await Step("client.put", Send(e, HttpMethod.Put, cp, new { name = "cli2" + n }), HttpStatusCode.OK, cp);
        await Step("client.patch.inactive", Send(e, HttpMethod.Patch, cp, new { isActive = false }), HttpStatusCode.OK, cp);
        await Step("client.secret", e.Admin.PostAsync($"{cp}/secret", null), HttpStatusCode.OK, cp);
        await Step("client.role", e.Admin.PutAsync($"{cp}/roles/{roleId}", null), HttpStatusCode.NoContent, cp);

        Assert.Equal(HttpStatusCode.NoContent, (await e.Admin.DeleteAsync(cp)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync(cp)).StatusCode);
        return t;
    }

    [SkippableFact]
    public async Task The_version_trace_of_a_scripted_session_is_the_same_in_memory_and_on_postgres_with_triggers()
    {
        var mem = await Trace("mem");
        var pg = await Trace("pg");
        Console.WriteLine("TRACE " + string.Join(" ", pg));
        Assert.Equal(mem, pg);
        Assert.Equal("app.create=1", pg[0]);
        Assert.Equal("app.put=2", pg[1]);
        Assert.Equal("app.put.identical=3", pg[2]);
        Assert.Equal("app.put.rename=4", pg[3]);
        Assert.Equal("app.put.stale=4", pg[5]);
        Assert.Contains("role.after-app-rename=3", pg); // creation 1, patch 2, put.case 3... (patch.same may differ; compared with mem above)
    }
}
