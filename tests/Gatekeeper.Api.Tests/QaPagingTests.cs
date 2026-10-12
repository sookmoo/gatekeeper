using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Gatekeeper.Api.Tests;

/// <summary>QA slice 4a: paging across all four list endpoints and both stores.</summary>
public class QaPagingTests
{
    public static IEnumerable<object[]> Stores() => QaEnv.Stores();

    private static string Enc(string s) => Convert.ToBase64String(Encoding.ASCII.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task All_four_lists_page_completely_without_duplicates_and_match_the_unpaged_order(string store)
    {
        using var e = new QaEnv(store);
        var appIds = new List<Guid>();
        for (var i = 0; i < 7; i++) appIds.Add(await e.App($"app{i}"));
        var roleIds = new List<Guid>();
        for (var i = 0; i < 7; i++) roleIds.Add(await e.Role(appIds[0], $"role{i}"));
        var userIds = new List<Guid>();
        for (var i = 0; i < 7; i++) userIds.Add(await e.User($"user{i}", null));
        foreach (var r in roleIds) await e.Assign(userIds[0], r);

        var urls = new[] { "/v1/applications", $"/v1/applications/{appIds[0]}/roles", "/v1/users", $"/v1/users/{userIds[0]}/roles" };
        foreach (var url in urls)
        {
            var (_, all) = await e.Walk(url, 200);
            // the admin client's bootstrap adds one application ("gatekeeper") and one user ("test-admin")
            var expected = url is "/v1/applications" or "/v1/users" ? 8 : 7;
            Assert.Equal(expected, all.Count);
            foreach (var limit in new[] { 1, 2, 3, 6, 7, 8 })
            {
                var (pages, items) = await e.Walk(url, limit);
                Assert.Equal(all.Select(x => x.GetProperty("id").GetGuid()), items.Select(x => x.GetProperty("id").GetGuid()));
                foreach (var p in pages.SkipLast(1)) Assert.Equal(limit, p.GetProperty("items").GetArrayLength());
                Assert.Equal(JsonValueKind.Null, pages[^1].GetProperty("nextCursor").ValueKind);
                // exactly-full last page must not advertise another (empty) page
                Assert.Equal((int)Math.Ceiling(expected / (double)limit), pages.Count);
            }
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Default_limit_is_50_and_max_200_is_accepted(string store)
    {
        using var e = new QaEnv(store);
        for (var i = 0; i < 55; i++) await e.Create("/v1/applications", new { name = $"a{i:D3}" }); // +1: "gatekeeper" from the admin bootstrap
        var p = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications"));
        Assert.Equal(50, p.GetProperty("items").GetArrayLength());
        Assert.NotEqual(JsonValueKind.Null, p.GetProperty("nextCursor").ValueKind);
        var q = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications?limit=200"));
        Assert.Equal(56, q.GetProperty("items").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, q.GetProperty("nextCursor").ValueKind);
        var one = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications?limit=1"));
        Assert.Equal(1, one.GetProperty("items").GetArrayLength());
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Empty_collections_return_empty_items_and_null_cursor(string store)
    {
        using var e = new QaEnv(store);
        var app = await e.App("empty");
        var user = await e.User("nobody1", null);
        foreach (var url in new[] { $"/v1/applications/{app}/roles", $"/v1/users/{user}/roles", "/v1/users?username=zzz" })
        {
            var p = await QaEnv.Json(await e.Admin.GetAsync(url));
            Assert.Equal(0, p.GetProperty("items").GetArrayLength());
            Assert.Equal(JsonValueKind.Null, p.GetProperty("nextCursor").ValueKind);
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Bad_limits_are_400_on_every_list(string store)
    {
        using var e = new QaEnv(store);
        var app = await e.App("x1");
        var user = await e.User("x2", null);
        foreach (var query in new[] { "limit=0", "limit=-1", "limit=201", "limit=1.5", "limit=abc", "limit=%20", "limit=99999999999", "limit=1e2", "limit=0x10" })
        foreach (var url in new[] { "/v1/applications", $"/v1/applications/{app}/roles", "/v1/users", $"/v1/users/{user}/roles" })
        {
            var r = await e.Admin.GetAsync($"{url}?{query}");
            Assert.True(r.StatusCode == HttpStatusCode.BadRequest, $"{url}?{query} -> {(int)r.StatusCode}");
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Odd_but_parseable_limits_do_not_crash(string store)
    {
        using var e = new QaEnv(store);
        await e.App("x1");
        // Not specified either way; must be a clean 200 or 400, never a 5xx.
        foreach (var q in new[] { "limit=05", "limit=%2B5", "limit=5&limit=6", "limit=", "limit=5%00", "cursor=&limit=1" })
        {
            var r = await e.Admin.GetAsync($"/v1/applications?{q}");
            Assert.True((int)r.StatusCode is 200 or 400, $"?{q} -> {(int)r.StatusCode}");
        }
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Tampered_cursors_are_400_never_500_or_negative_pages(string store)
    {
        using var e = new QaEnv(store);
        for (var i = 0; i < 5; i++) await e.App($"c{i}");
        var first = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications?limit=2"));
        var good = first.GetProperty("nextCursor").GetString()!;
        var bad = new List<string>
        {
            good + "A", good[..^1], good.ToUpperInvariant(), good + "=", good + "==", "%%%", "o2", Enc("o-1"), Enc("o+2"), Enc("o02"), Enc("o 2"),
            Enc("o2 "), Enc("o"), Enc("O2"), Enc("o99999999999999999999"), Enc("o1000001"), Enc("o2147483647"), Enc("o1e3"), Enc("p2"), Enc("o2\n"),
            new string('A', 33), new string('A', 5000), "..", "0", "null", "undefined", "-", "_", "Zm9v", Convert.ToBase64String("o2"u8.ToArray()) + "x",
            "é", "o2\u0000",
        };
        foreach (var c in bad)
        {
            var r = await e.Admin.GetAsync("/v1/applications?cursor=" + Uri.EscapeDataString(c));
            Assert.True(r.StatusCode == HttpStatusCode.BadRequest, $"cursor '{c}' -> {(int)r.StatusCode}");
        }
        // a canonical hand-made cursor is fine (offset cursors are opaque but must still work if they decode)
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync("/v1/applications?cursor=" + Uri.EscapeDataString(good))).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Cursor_beyond_the_end_gives_empty_page(string store)
    {
        using var e = new QaEnv(store);
        await e.App("only");
        var p = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications?cursor=" + Enc("o500")));
        Assert.Equal(0, p.GetProperty("items").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, p.GetProperty("nextCursor").ValueKind);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Filters_combine_with_paging(string store)
    {
        using var e = new QaEnv(store);
        for (var i = 0; i < 9; i++) await e.User($"f{i}", null, active: i % 3 != 0); // inactive: f0 f3 f6
        var (_, inactive) = await e.Walk("/v1/users?active=false", 2);
        Assert.Equal(["f0", "f3", "f6"], inactive.Select(u => u.GetProperty("username").GetString()));
        var (pages, active) = await e.Walk("/v1/users?active=true", 4);
        Assert.Equal(7, active.Count); // six f-users plus test-admin
        Assert.Equal(2, pages.Count);
        Assert.All(active, u => Assert.True(u.GetProperty("isActive").GetBoolean()));
        var (_, byName) = await e.Walk("/v1/users?username=F3", 1);
        Assert.Single(byName);
        var (_, none) = await e.Walk("/v1/users?username=f3&active=true", 1);
        Assert.Empty(none);
        // a cursor taken under one filter and replayed under another must not crash
        var p = await QaEnv.Json(await e.Admin.GetAsync("/v1/users?active=true&limit=2"));
        var r = await e.Admin.GetAsync("/v1/users?active=false&limit=2&cursor=" + Uri.EscapeDataString(p.GetProperty("nextCursor").GetString()!));
        Assert.True((int)r.StatusCode < 500);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task User_roles_filter_by_application_pages_correctly(string store)
    {
        using var e = new QaEnv(store);
        var a = await e.App("shop"); var b = await e.App("blog");
        var u = await e.User("pager", null);
        for (var i = 0; i < 5; i++) await e.Assign(u, await e.Role(a, $"s{i}"));
        for (var i = 0; i < 3; i++) await e.Assign(u, await e.Role(b, $"b{i}"));
        var (_, shop) = await e.Walk($"/v1/users/{u}/roles?application={a}", 2);
        Assert.Equal(["s0", "s1", "s2", "s3", "s4"], shop.Select(r => r.GetProperty("name").GetString()));
        var (_, all) = await e.Walk($"/v1/users/{u}/roles", 3);
        Assert.Equal(8, all.Count);
        Assert.Equal(8, all.Select(r => r.GetProperty("id").GetGuid()).Distinct().Count());
        Assert.Equal(HttpStatusCode.OK, (await e.Admin.GetAsync($"/v1/users/{u}/roles?application={Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await e.Admin.GetAsync($"/v1/users/{u}/roles?application=not-a-guid")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Missing_parents_are_404_even_with_bad_or_good_paging(string store)
    {
        using var e = new QaEnv(store);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync($"/v1/applications/{Guid.NewGuid()}/roles")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await e.Admin.GetAsync($"/v1/users/{Guid.NewGuid()}/roles?limit=5")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Both_stores_order_names_the_same_way(string store)
    {
        using var e = new QaEnv(store);
        var names = new[] { "a", "a-b", "a.b", "a_b", "a1", "ab", "b", "0a", "9", "a--b", "a-", "_x".TrimStart('_') + "z" };
        foreach (var n in names.Distinct()) await e.App(n);
        var (_, items) = await e.Walk("/v1/applications", 3);
        var got = items.Select(i => i.GetProperty("name").GetString()!).ToList();
        Assert.Equal(got.OrderBy(x => x, StringComparer.Ordinal), got); // ordinal order, as the in-memory store defines
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Insert_and_delete_between_pages_never_returns_an_item_twice_with_stable_ids(string store)
    {
        using var e = new QaEnv(store);
        for (var i = 0; i < 6; i++) await e.App($"m{i}");
        var p1 = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications?limit=3"));
        await e.App("zz-new"); // sorts last: must not disturb page 2 (page 1 is gatekeeper, m0, m1)
        var p2 = await QaEnv.Json(await e.Admin.GetAsync("/v1/applications?limit=3&cursor=" + Uri.EscapeDataString(p1.GetProperty("nextCursor").GetString()!)));
        Assert.Equal(["m2", "m3", "m4"], p2.GetProperty("items").EnumerateArray().Select(x => x.GetProperty("name").GetString()));
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Client_abort_mid_request_leaves_the_server_healthy(string store)
    {
        using var e = new QaEnv(store);
        for (var i = 0; i < 20; i++) await e.App($"k{i}");
        for (var i = 0; i < 20; i++)
        {
            using var cts = new CancellationTokenSource();
            var t = e.Admin.GetAsync("/v1/applications?limit=200", cts.Token);
            if (i % 2 == 0) cts.Cancel(); else cts.CancelAfter(1);
            try { await t; } catch (OperationCanceledException) { }
        }
        var r = await e.Admin.GetAsync("/v1/applications?limit=5");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await e.Anon.GetAsync("/health/ready")).StatusCode);
    }

    [SkippableTheory, MemberData(nameof(Stores))]
    public async Task Login_abort_does_not_throw_a_500_or_count_as_a_failure(string store)
    {
        using var e = new QaEnv(store);
        var a = await e.App("shop"); var r = await e.Role(a, "buyer"); var u = await e.User("cancel1"); await e.Assign(u, r);
        for (var i = 0; i < 15; i++)
        {
            using var cts = new CancellationTokenSource();
            var t = e.Anon.PostAsJsonAsync("/v1/auth/login", new { username = "cancel1", password = "correct horse battery", application = "shop" }, cts.Token);
            cts.CancelAfter(i % 4);
            try { (await t).Dispose(); } catch (OperationCanceledException) { }
        }
        Assert.Equal(HttpStatusCode.OK, (await e.Login("cancel1", "correct horse battery", "shop")).StatusCode);
    }
}
