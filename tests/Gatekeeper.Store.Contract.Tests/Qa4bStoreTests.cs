using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;
using Gatekeeper.Tests;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>QA slice 4b: client and audit repositories, same assertions against both stores.</summary>
public abstract class Qa4bStoreTests : IDisposable
{
    protected abstract bool HonoursCancellation { get; }
    protected abstract (IAppRepository A, IRoleRepository R, IUserRepository U, IClientRepository C, IAuditRepository Au) Open();
    public virtual void Dispose() => GC.SuppressFinalize(this);

    private static Client NewClient(App app, string name, bool active = true) =>
        new(Guid.NewGuid(), name, app.Id, active, Clock.UtcNowMicros(), Clock.UtcNowMicros());

    protected static AuditEvent Ev(string actor = "a", string action = "x", DateTimeOffset? at = null, string? target = null, string? detail = null) =>
        new(Guid.NewGuid(), at ?? Clock.UtcNowMicros(), actor, action, target, AuditEvent.Success, detail, null);

    [SkippableFact]
    public async Task Client_names_are_case_insensitive_everywhere()
    {
        var (apps, _, _, clients, _) = Open();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var c = await clients.AddAsync(NewClient(app, "svc"), "h");
        await Assert.ThrowsAsync<ConflictException>(() => clients.AddAsync(NewClient(app, "SVC"), "h"));
        var d = await clients.AddAsync(NewClient(app, "other"), "h");
        await Assert.ThrowsAsync<ConflictException>(() => clients.UpdateAsync(d with { Name = "Svc" }));
        // case-only rename of itself must work
        var r = await clients.UpdateAsync(c with { Name = "SVC" });
        Assert.Equal("SVC", r!.Name);
        Assert.Equal(c.Id, (await clients.GetByNameAsync("svc"))!.Id);
    }

    [SkippableFact]
    public async Task Client_update_ignores_app_and_created_at_and_keeps_secret()
    {
        var (apps, _, _, clients, _) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var b = await apps.AddAsync(new App(Guid.NewGuid(), "b1"));
        var c = await clients.AddAsync(NewClient(a, "svc"), "h1");
        var u = await clients.UpdateAsync(c with { AppId = b.Id, CreatedAt = DateTimeOffset.UnixEpoch, IsActive = false });
        Assert.Equal(a.Id, u!.AppId);
        Assert.Equal(c.CreatedAt, u.CreatedAt);
        Assert.Equal("h1", await clients.GetSecretHashAsync(c.Id));
        Assert.Equal(a.Id, (await clients.GetAsync(c.Id))!.AppId);
    }

    [SkippableFact]
    public async Task Cascades_app_role_client()
    {
        var (apps, roles, _, clients, _) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var b = await apps.AddAsync(new App(Guid.NewGuid(), "b1"));
        var r1 = await roles.AddAsync(new Role(Guid.NewGuid(), a.Id, "r1", ""));
        var r2 = await roles.AddAsync(new Role(Guid.NewGuid(), a.Id, "r2", ""));
        var c = await clients.AddAsync(NewClient(a, "svc"), "h");
        var keep = await clients.AddAsync(NewClient(b, "keep"), "h");
        await clients.AssignRoleAsync(c.Id, r1.Id);
        await clients.AssignRoleAsync(c.Id, r2.Id);
        await roles.DeleteAsync(r1.Id);
        Assert.Equal(["r2"], (await clients.ListRolesAsync(c.Id)).Select(r => r.Name));
        Assert.False(await clients.RevokeRoleAsync(c.Id, r1.Id));
        await apps.DeleteAsync(a.Id);
        Assert.Null(await clients.GetAsync(c.Id));
        Assert.Null(await clients.GetSecretHashAsync(c.Id));
        Assert.Null(await clients.GetByNameAsync("svc"));
        Assert.Empty(await clients.ListRolesAsync(c.Id));
        Assert.Equal(["keep"], (await clients.ListAsync()).Select(x => x.Name));
        Assert.False(await clients.SetSecretHashAsync(c.Id, "x", DateTimeOffset.UtcNow));
        Assert.False(await clients.DeleteAsync(c.Id));
        // name is free again
        await clients.AddAsync(NewClient(b, "svc"), "h");
        Assert.NotNull(keep);
    }

    [SkippableFact]
    public async Task Assign_errors_and_idempotence()
    {
        var (apps, roles, _, clients, _) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var r = await roles.AddAsync(new Role(Guid.NewGuid(), a.Id, "r1", ""));
        var c = await clients.AddAsync(NewClient(a, "svc"), "h");
        await clients.AssignRoleAsync(c.Id, r.Id);
        await clients.AssignRoleAsync(c.Id, r.Id);
        Assert.Single(await clients.ListRolesAsync(c.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => clients.AssignRoleAsync(c.Id, Guid.NewGuid()));
        await Assert.ThrowsAsync<NotFoundException>(() => clients.AssignRoleAsync(Guid.NewGuid(), r.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => clients.AssignRoleAsync(Guid.NewGuid(), Guid.NewGuid()));
        Assert.True(await clients.RevokeRoleAsync(c.Id, r.Id));
        Assert.False(await clients.RevokeRoleAsync(c.Id, r.Id));
        // Deleting the client removes assignments; role stays
        await clients.AssignRoleAsync(c.Id, r.Id);
        await clients.DeleteAsync(c.Id);
        Assert.NotNull(await roles.GetAsync(r.Id));
    }

    [SkippableFact]
    public async Task Client_list_order_paging_and_filter_are_stable_and_identical()
    {
        var (apps, _, _, clients, _) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var b = await apps.AddAsync(new App(Guid.NewGuid(), "b1"));
        var names = new[] { "a-b", "a.b", "a_b", "ab", "a1", "a-1", "0z", "Z9".ToLowerInvariant(), "a--b", "a-", "b", "a" };
        foreach (var (n, i) in names.Select((n, i) => (n, i))) await clients.AddAsync(NewClient(i % 2 == 0 ? a : b, n), "h");
        var all = (await clients.ListAsync()).Select(c => c.Name).ToList();
        // Ordinal (byte) order is what the in-memory store and the C-collated database both give for the slug alphabet.
        Assert.Equal(names.Order(StringComparer.Ordinal), all);
        var paged = new List<string>();
        for (var off = 0; ; off += 5) { var p = await clients.ListAsync(slice: new Slice(off, 5)); paged.AddRange(p.Select(c => c.Name)); if (p.Count < 5) break; }
        Assert.Equal(all, paged);
        Assert.Equal(6, (await clients.ListAsync(a.Id)).Count);
        Assert.Empty(await clients.ListAsync(Guid.NewGuid()));
        Assert.Empty(await clients.ListAsync(slice: new Slice(100, 5)));
    }

    [SkippableFact]
    public async Task Concurrent_duplicate_client_names_yield_exactly_one_winner()
    {
        var (apps, _, _, clients, _) = Open();
        var a = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(i => Task.Run(async () =>
        {
            try { await clients.AddAsync(NewClient(a, i % 2 == 0 ? "dup" : "DUP"), "h"); return "ok"; }
            catch (ConflictException) { return "conflict"; }
        })));
        Assert.Equal(1, results.Count(r => r == "ok"));
        Assert.Equal(15, results.Count(r => r == "conflict"));
        Assert.Single(await clients.ListAsync());
    }

    [SkippableFact]
    public async Task Concurrent_delete_app_and_add_client_leaves_no_orphans()
    {
        var (apps, _, _, clients, _) = Open();
        for (var round = 0; round < 15; round++)
        {
            var a = await apps.AddAsync(new App(Guid.NewGuid(), $"a{round}"));
            var add = Task.Run(async () => { try { await clients.AddAsync(NewClient(a, $"c{round}"), "h"); } catch (NotFoundException) { } });
            var del = Task.Run(() => apps.DeleteAsync(a.Id));
            await Task.WhenAll(add, del);
            Assert.Empty(await clients.ListAsync(a.Id));
        }
    }

    [SkippableFact]
    public async Task Audit_is_newest_first_with_stable_tie_break_and_exact_filters()
    {
        var (_, _, _, _, audit) = Open();
        var t0 = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var same = Enumerable.Range(0, 7).Select(_ => Ev("u1", "A", t0)).ToList();
        foreach (var e in same) await audit.AppendAsync(e);
        await audit.AppendAsync(Ev("U1", "a", t0.AddSeconds(1)));
        await audit.AppendAsync(Ev("u2", "A", t0.AddSeconds(-1)));
        var all = await audit.ListAsync();
        Assert.Equal(9, all.Count);
        Assert.Equal("U1", all[0].Actor);
        Assert.Equal("u2", all[^1].Actor);
        Assert.Equal(same.Select(e => e.Id).OrderDescending(Comparer<Guid>.Create(AuditKey.CompareIds)), all.Skip(1).Take(7).Select(e => e.Id));
        Assert.Single(await audit.ListAsync(actor: "U1"));
        Assert.Equal(8, (await audit.ListAsync(action: "A")).Count);
        Assert.Equal(7, (await audit.ListAsync("u1", "A")).Count);
        var walked = new List<Guid>();
        AuditKey? after = null;
        while (true) { var p = await audit.ListAsync(after: after, take: 2); walked.AddRange(p.Select(e => e.Id)); if (p.Count < 2) break; after = new AuditKey(p[^1].At, p[^1].Id); }
        Assert.Equal(all.Select(e => e.Id), walked);
        Assert.Empty(await audit.ListAsync(after: new AuditKey(all[^1].At, all[^1].Id), take: 5));
        Assert.Empty(await audit.ListAsync(actor: "%"));
        Assert.Empty(await audit.ListAsync(actor: "u_"));
    }

    [SkippableFact]
    public async Task Audit_round_trips_values_and_precision()
    {
        var (_, _, _, _, audit) = Open();
        var at = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero).AddTicks(1234560); // 123456 microseconds
        var e = new AuditEvent(Guid.NewGuid(), at, "actor", "PUT /v1/x/{id}", "id=1 role=2", AuditEvent.Failure, "détail 日本語 😀", "::1");
        await audit.AppendAsync(e);
        var back = Assert.Single(await audit.ListAsync());
        Assert.Equal(e, back);
        var e2 = Ev(target: null, detail: null);
        await audit.AppendAsync(e2);
        Assert.Contains(await audit.ListAsync(), x => x.Id == e2.Id && x.Target is null && x.Detail is null && x.Address is null);
        // empty strings are not null
        var e3 = Ev(target: "", detail: "");
        await audit.AppendAsync(e3);
        Assert.Contains(await audit.ListAsync(), x => x.Id == e3.Id && x.Target == "" && x.Detail == "");
    }

    [SkippableFact]
    public async Task Audit_filter_with_nul_or_lone_surrogate_behaves_the_same_in_both_stores()
    {
        var (_, _, _, _, audit) = Open();
        await audit.AppendAsync(Ev());
        foreach (var bad in new[] { "a\0b", "\uD800", "x\uDC00y" })
        {
            Assert.Empty(await audit.ListAsync(actor: bad));
            Assert.Empty(await audit.ListAsync(action: bad));
        }
    }

    [SkippableFact]
    public async Task Audit_duplicate_id_is_rejected_the_same_way()
    {
        var (_, _, _, _, audit) = Open();
        var e = Ev();
        await audit.AppendAsync(e);
        var ex = await Record.ExceptionAsync(() => audit.AppendAsync(e));
        Assert.NotNull(ex); // append-only log must not silently double-record / overwrite
        Assert.Single(await audit.ListAsync());
    }

    [SkippableFact]
    public async Task Concurrent_audit_appends_are_all_kept()
    {
        var (_, _, _, _, audit) = Open();
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() => audit.AppendAsync(Ev($"u{i % 3}")))));
        Assert.Equal(40, (await audit.ListAsync(take: 500)).Count);
    }

    [SkippableFact]
    public async Task Cancelled_token_stops_new_methods()
    {
        var (apps, roles, _, clients, audit) = Open();
        var app = await apps.AddAsync(new App(Guid.NewGuid(), "a1"));
        var role = await roles.AddAsync(new Role(Guid.NewGuid(), app.Id, "r1", ""));
        var c = await clients.AddAsync(NewClient(app, "svc"), "h");
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var ct = cts.Token;
        var calls = new (string, Func<Task>)[]
        {
            ("c.Add", () => clients.AddAsync(NewClient(app, "late"), "h", ct)), ("c.Get", () => clients.GetAsync(c.Id, ct)),
            ("c.ByName", () => clients.GetByNameAsync("svc", ct)), ("c.List", () => clients.ListAsync(null, null, ct)),
            ("c.Update", () => clients.UpdateAsync(c with { Name = "renamed" }, ct)), ("c.Delete", () => clients.DeleteAsync(c.Id, ct)),
            ("c.SetSecret", () => clients.SetSecretHashAsync(c.Id, "zz", DateTimeOffset.UtcNow, ct)),
            ("c.GetSecret", () => clients.GetSecretHashAsync(c.Id, ct)), ("c.Assign", () => clients.AssignRoleAsync(c.Id, role.Id, ct)),
            ("c.Revoke", () => clients.RevokeRoleAsync(c.Id, role.Id, ct)), ("c.Roles", () => clients.ListRolesAsync(c.Id, null, ct)),
            ("a.Append", () => audit.AppendAsync(Ev(), ct)), ("a.List", () => audit.ListAsync(null, null, null, null, ct)),
        };
        var ignored = new List<string>();
        foreach (var (name, call) in calls)
        {
            var ex = await Record.ExceptionAsync(call);
            if (HonoursCancellation) Assert.True(ex is OperationCanceledException, $"{name}: {ex?.GetType().Name ?? "no exception"}");
            else if (ex is null) ignored.Add(name);
        }
        if (!HonoursCancellation) return;
        // writes must not have been applied by a cancelled call
        Assert.Equal("svc", (await clients.GetAsync(c.Id))!.Name);
        Assert.Equal("h", await clients.GetSecretHashAsync(c.Id));
        Assert.Empty(await clients.ListRolesAsync(c.Id));
        Assert.Null(await clients.GetByNameAsync("late"));
        if (HonoursCancellation) Assert.Empty(await audit.ListAsync());
    }
}

public class InMemoryQa4bStoreTests : Qa4bStoreTests
{
    protected override bool HonoursCancellation => false;
    protected override (IAppRepository, IRoleRepository, IUserRepository, IClientRepository, IAuditRepository) Open()
    {
        var s = new InMemoryStore();
        return (new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s), new InMemoryClientRepository(s), new InMemoryAuditRepository(s));
    }
}

public class PostgresQa4bStoreTests : Qa4bStoreTests
{
    private readonly List<ServiceProvider> _providers = [];
    private readonly List<PgTestDatabase> _dbs = [];
    protected override bool HonoursCancellation => true;

    protected override (IAppRepository, IRoleRepository, IUserRepository, IClientRepository, IAuditRepository) Open()
    {
        var db = PgTestDatabase.TryCreate();
        Skip.If(db is null, "GATEKEEPER_TEST_PG is not set; Postgres tests skipped.");
        _dbs.Add(db!);
        var p = PgStores.OpenAsAppRole(db!);
        _providers.Add(p);
        return (p.GetRequiredService<IAppRepository>(), p.GetRequiredService<IRoleRepository>(), p.GetRequiredService<IUserRepository>(),
            p.GetRequiredService<IClientRepository>(), p.GetRequiredService<IAuditRepository>());
    }

    public override void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var d in _dbs) d.Dispose();
        base.Dispose();
    }

    [SkippableFact]
    public async Task Qa6c_keyset_extreme_and_adjacent_keys_and_sub_microsecond_cursors()
    {
        var (_, _, _, _, au) = Open();
        var t = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero);
        var lo = Guid.Parse("00000000-0000-0000-0000-000000000001");
        var hi = Guid.Parse("ffffffff-ffff-ffff-ffff-fffffffffffe");
        // rows exactly one microsecond apart (the smallest step stored), same ids reused across instants
        var rows = new[] { Ev(at: t.AddTicks(-10)), Ev(at: t), Ev(at: t.AddTicks(10)) };
        foreach (var r in rows) await au.AppendAsync(r);
        Assert.Equal(3, (await au.ListAsync(after: new AuditKey(DateTimeOffset.MaxValue, Guid.Empty))).Count);
        Assert.Equal(3, (await au.ListAsync(after: new AuditKey(new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero), hi))).Count);
        Assert.Empty(await au.ListAsync(after: new AuditKey(DateTimeOffset.MinValue, hi)));
        Assert.Empty(await au.ListAsync(after: new AuditKey(new DateTimeOffset(1, 1, 1, 0, 0, 0, TimeSpan.Zero), Guid.Empty)));
        // strictness on the exact key at the microsecond and with ids at the extremes
        Assert.Equal(2, (await au.ListAsync(after: new AuditKey(t.AddTicks(10), Guid.Empty))).Count);
        Assert.Equal(3, (await au.ListAsync(after: new AuditKey(t.AddTicks(10), hi))).Count);
        Assert.Equal(2, (await au.ListAsync(after: new AuditKey(t.AddTicks(10), lo))).Count);
    }

    [SkippableFact]
    public async Task Qa6c_keys_on_whole_microseconds_mean_the_same_in_both_stores()
    {
        // The API refuses cursors that are not whole microseconds, so the stores only ever see whole-microsecond keys.
        var (_, _, _, _, au) = Open();
        var t = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero);
        var a = Ev(at: t); var b = Ev(at: t.AddTicks(10));
        await au.AppendAsync(a); await au.AppendAsync(b);
        Assert.Equal([a.Id], (await au.ListAsync(after: new AuditKey(t.AddTicks(10), Guid.Empty))).Select(e => e.Id));
        Assert.Equal([b.Id, a.Id], (await au.ListAsync(after: new AuditKey(t.AddTicks(20), Guid.Empty))).Select(e => e.Id));
    }
}
