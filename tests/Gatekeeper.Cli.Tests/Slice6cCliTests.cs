using System.Net;
using System.Text;
using Gatekeeper.Cli;

namespace Gatekeeper.Cli.Tests;

/// <summary>Slice 6c: `gk audit list` is unchanged by the keyset cursor (one page, the cursor is not used or shown).</summary>
public class Slice6cCliTests
{
    private sealed class Recording(List<string> seen) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            seen.Add(request.RequestUri!.PathAndQuery);
            const string body = "{\"items\":[{\"at\":\"2026-01-01T00:00:00Z\",\"outcome\":\"success\",\"actor\":\"a\",\"action\":\"b\",\"target\":null,\"detail\":\"d\"}],\"nextCursor\":\"azgXRQ5YAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    [Fact]
    public async Task Audit_list_sends_no_cursor_and_ignores_the_one_it_receives()
    {
        var seen = new List<string>();
        var o = new StringWriter(); var e = new StringWriter();
        var code = await CliApp.RunAsync(["audit", "list", "--actor", "a", "--limit", "5"],
            _ => new HttpClient(new Recording(seen)) { BaseAddress = new Uri("http://localhost:5080") }, o, e, new MemoryTokenStore(), (_, _) => null);
        Assert.Equal(0, code);
        Assert.Equal(["/v1/audit?limit=5&actor=a"], seen);
        Assert.DoesNotContain("azgXRQ5Y", o.ToString());
    }
}
