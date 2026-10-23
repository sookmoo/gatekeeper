using Gatekeeper.Application;
using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Store.Contract.Tests;

/// <summary>Behaviour every store implementation must satisfy. Subclass per store.</summary>
public abstract class StoreContract : IDisposable
{
    public virtual void Dispose() => GC.SuppressFinalize(this);

    protected abstract (IAppRepository Apps, IRoleRepository Roles, IUserRepository Users) CreateStore();

    /// <summary>Set by <see cref="CreateStore"/>.</summary>
    protected ICredentialRepository Credentials { get; set; } = null!;
    protected IAuditRepository Audit { get; set; } = null!;
    protected IClientRepository Clients { get; set; } = null!;
    protected ISessionRepository Sessions { get; set; } = null!;
    /// <summary>Postgres only: a connection as the data-only app role, to prove the audit table is append-only.</summary>
    protected string? AppConnection { get; set; }

    private static User NewUser(string name, string? email = null) =>
        new(Guid.NewGuid(), name, email ?? $"{name}@example.com", name, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    private static App NewApp(string name) => new(Guid.NewGuid(), name);

    private static Role NewRole(App app, string name) => new(Guid.NewGuid(), app.Id, name, "");

    [SkippableFact]
    public async Task User_kind_and_expiry_round_trip_and_can_be_filtered_on()
    {
        var (_, _, users) = CreateStore();
        var now = new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
        var expires = now.AddDays(30).AddTicks(10);
        var person = await users.AddAsync(NewUser("alice"));
        var test = await users.AddAsync(NewUser("tester") with { Kind = UserKind.Test, ExpiresAt = expires });
        var shared = await users.AddAsync(NewUser("team") with { Kind = UserKind.Shared });

        Assert.Equal(UserKind.Person, (await users.GetAsync(person.Id))!.Kind);
        Assert.Null((await users.GetAsync(person.Id))!.ExpiresAt);
        var got = (await users.GetAsync(test.Id))!;
        Assert.Equal(UserKind.Test, got.Kind);
        Assert.Equal(expires, got.ExpiresAt);
        Assert.Equal(["tester"], (await users.ListAsync(kind: UserKind.Test)).Select(u => u.Username));
        Assert.Equal(["team"], (await users.ListAsync(kind: UserKind.Shared)).Select(u => u.Username));
        Assert.Equal(3, (await users.ListAsync()).Count);

        var changed = await users.UpdateAsync(got with { Kind = UserKind.Person, ExpiresAt = null });
        Assert.Equal(UserKind.Person, changed!.Kind);
        Assert.Null((await users.GetAsync(test.Id))!.ExpiresAt);
        Assert.Equal(UserKind.Shared, (await users.GetAsync(shared.Id))!.Kind);
    }

    [SkippableFact]
    public async Task Lists_are_ordered_and_sliced_consistently()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a0"));
        foreach (var n in new[] { "c", "a", "d", "b" }) await apps.AddAsync(NewApp($"app-{n}"));
        Assert.Equal(["a0", "app-a", "app-b", "app-c", "app-d"], (await apps.ListAsync()).Select(a => a.Name));
        Assert.Equal(["app-a", "app-b"], (await apps.ListAsync(new Slice(1, 2))).Select(a => a.Name));
        Assert.Empty(await apps.ListAsync(new Slice(5, 3)));

        foreach (var n in new[] { "r3", "r1", "r2" }) await roles.AddAsync(NewRole(app, n));
        Assert.Equal(["r2", "r3"], (await roles.ListByAppAsync(app.Id, new Slice(1, 5))).Select(r => r.Name));

        foreach (var n in new[] { "u3", "u1", "u2" }) await users.AddAsync(NewUser(n));
        Assert.Equal(["u1", "u2"], (await users.ListAsync(slice: new Slice(0, 2))).Select(u => u.Username));
        Assert.Equal(["u3"], (await users.ListAsync(slice: new Slice(2, 2))).Select(u => u.Username));

        var u1 = (await users.ListAsync(username: "u1")).Single();
        foreach (var r in await roles.ListByAppAsync(app.Id)) await users.AssignRoleAsync(u1.Id, r.Id);
        Assert.Equal(["r1", "r2"], (await users.ListRolesAsync(u1.Id, slice: new Slice(0, 2))).Select(r => r.Name));
    }

    private static Client NewClient(App app, string name, bool active = true) =>
        new(Guid.NewGuid(), name, app.Id, active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    [SkippableFact]
    public async Task Clients_crud_secret_roles_and_cascades()
    {
        var (apps, roles, _) = CreateStore();
        var app = await apps.AddAsync(NewApp("shop"));
        var other = await apps.AddAsync(NewApp("blog"));
        var r1 = await roles.AddAsync(NewRole(app, "reader"));
        var r2 = await roles.AddAsync(NewRole(app, "writer"));

        var c = await Clients.AddAsync(NewClient(app, "checkout"), "hash-1");
        Assert.Equal("hash-1", await Clients.GetSecretHashAsync(c.Id));
        Assert.Equal(c.Id, (await Clients.GetByNameAsync("CHECKOUT"))!.Id);
        await Assert.ThrowsAsync<ConflictException>(() => Clients.AddAsync(NewClient(other, "Checkout"), "h"));
        await Assert.ThrowsAsync<NotFoundException>(() => Clients.AddAsync(new Client(Guid.NewGuid(), "ghost", Guid.NewGuid(), true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), "h"));
        Assert.Null(await Clients.GetByNameAsync("ghost"));

        var second = await Clients.AddAsync(NewClient(other, "feed"), "hash-2");
        Assert.Equal(["checkout", "feed"], (await Clients.ListAsync()).Select(x => x.Name));
        Assert.Equal(["feed"], (await Clients.ListAsync(other.Id)).Select(x => x.Name));
        Assert.Equal(["feed"], (await Clients.ListAsync(slice: new Slice(1, 5))).Select(x => x.Name));

        // Update changes name/active only; the application stays.
        var updated = await Clients.UpdateAsync(c with { Name = "checkout2", IsActive = false, AppId = other.Id });
        Assert.Equal((app.Id, "checkout2", false), (updated!.AppId, updated.Name, updated.IsActive));
        await Assert.ThrowsAsync<ConflictException>(() => Clients.UpdateAsync(c with { Name = "FEED" }));
        Assert.Null(await Clients.UpdateAsync(c with { Id = Guid.NewGuid() }));

        Assert.True(await Clients.SetSecretHashAsync(c.Id, "hash-3", DateTimeOffset.UtcNow));
        Assert.Equal("hash-3", await Clients.GetSecretHashAsync(c.Id));
        Assert.False(await Clients.SetSecretHashAsync(Guid.NewGuid(), "x", DateTimeOffset.UtcNow));

        await Clients.AssignRoleAsync(c.Id, r2.Id);
        await Clients.AssignRoleAsync(c.Id, r1.Id);
        await Clients.AssignRoleAsync(c.Id, r1.Id); // idempotent
        Assert.Equal(["reader", "writer"], (await Clients.ListRolesAsync(c.Id)).Select(r => r.Name));
        Assert.Equal(["writer"], (await Clients.ListRolesAsync(c.Id, new Slice(1, 5))).Select(r => r.Name));
        await Assert.ThrowsAsync<NotFoundException>(() => Clients.AssignRoleAsync(Guid.NewGuid(), r1.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => Clients.AssignRoleAsync(c.Id, Guid.NewGuid()));

        // Deleting a role drops the assignment; deleting the app drops its clients, their secrets and assignments.
        Assert.True(await roles.DeleteAsync(r1.Id));
        Assert.Equal(["writer"], (await Clients.ListRolesAsync(c.Id)).Select(r => r.Name));
        Assert.True(await Clients.RevokeRoleAsync(c.Id, r2.Id));
        Assert.False(await Clients.RevokeRoleAsync(c.Id, r2.Id));
        await Clients.AssignRoleAsync(c.Id, r2.Id);
        Assert.True(await apps.DeleteAsync(app.Id));
        Assert.Null(await Clients.GetAsync(c.Id));
        Assert.Null(await Clients.GetSecretHashAsync(c.Id));
        Assert.NotNull(await Clients.GetAsync(second.Id));
        Assert.True(await Clients.DeleteAsync(second.Id));
        Assert.False(await Clients.DeleteAsync(second.Id));
    }

    [SkippableFact]
    public async Task Sessions_rotate_by_compare_and_set_revoke_expire_and_cascade()
    {
        var (apps, _, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("shop"));
        var user = await users.AddAsync(NewUser("alice"));
        var now = new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        Session New(DateTimeOffset created, TimeSpan life) => new(Guid.NewGuid(), user.Id, app.Id, created, created, created + life, null);

        var s1 = New(now, TimeSpan.FromDays(30));
        await Sessions.AddAsync(s1, "h1");
        await Assert.ThrowsAsync<NotFoundException>(() => Sessions.AddAsync(New(now, TimeSpan.FromDays(1)) with { UserId = Guid.NewGuid() }, "x"));
        await Assert.ThrowsAsync<NotFoundException>(() => Sessions.AddAsync(New(now, TimeSpan.FromDays(1)) with { AppId = Guid.NewGuid() }, "x"));
        Assert.Equal(s1, await Sessions.GetAsync(s1.Id));
        Assert.Equal(new SessionHashes("h1", null), await Sessions.GetHashesAsync(s1.Id));
        Assert.Null(await Sessions.GetAsync(Guid.NewGuid()));
        Assert.Null(await Sessions.GetHashesAsync(Guid.NewGuid()));

        // Rotation: only with the current hash; the old one is kept as the previous.
        var later = now.AddMinutes(5);
        Assert.False(await Sessions.RotateAsync(s1.Id, "wrong", "h2", later));
        Assert.True(await Sessions.RotateAsync(s1.Id, "h1", "h2", later));
        Assert.False(await Sessions.RotateAsync(s1.Id, "h1", "h3", later)); // already replaced
        Assert.Equal(new SessionHashes("h2", "h1"), await Sessions.GetHashesAsync(s1.Id));
        Assert.Equal(later, (await Sessions.GetAsync(s1.Id))!.LastUsedAt);
        Assert.False(await Sessions.RotateAsync(Guid.NewGuid(), "h1", "h2", later));

        // Expired sessions cannot rotate.
        var shortLived = New(now, TimeSpan.FromMinutes(1));
        await Sessions.AddAsync(shortLived, "e1");
        Assert.False(await Sessions.RotateAsync(shortLived.Id, "e1", "e2", now.AddMinutes(2)));

        // Listing: active only, newest first, sliced.
        var s2 = New(now.AddHours(1), TimeSpan.FromDays(30));
        var s3 = New(now.AddHours(2), TimeSpan.FromDays(30));
        await Sessions.AddAsync(s2, "g1");
        await Sessions.AddAsync(s3, "k1");
        var check = now.AddHours(3);
        Assert.Equal([s3.Id, s2.Id, s1.Id], (await Sessions.ListActiveByUserAsync(user.Id, check)).Select(x => x.Id));
        Assert.Equal([s2.Id], (await Sessions.ListActiveByUserAsync(user.Id, check, new Slice(1, 1))).Select(x => x.Id));
        Assert.Empty(await Sessions.ListActiveByUserAsync(Guid.NewGuid(), check));

        // Revoke is idempotent and keeps the first revocation time; revoked sessions leave the list and cannot rotate.
        Assert.True(await Sessions.RevokeAsync(s2.Id, check));
        Assert.True(await Sessions.RevokeAsync(s2.Id, check.AddHours(1)));
        Assert.Equal(check, (await Sessions.GetAsync(s2.Id))!.RevokedAt);
        Assert.False(await Sessions.RevokeAsync(Guid.NewGuid(), check));
        Assert.False(await Sessions.RotateAsync(s2.Id, "g1", "g2", check));
        Assert.Equal([s3.Id, s1.Id], (await Sessions.ListActiveByUserAsync(user.Id, check)).Select(x => x.Id));
        Assert.Equal(2, await Sessions.RevokeAllForUserAsync(user.Id, check));
        Assert.Equal(0, await Sessions.RevokeAllForUserAsync(user.Id, check));
        Assert.Empty(await Sessions.ListActiveByUserAsync(user.Id, check));

        // Purge removes sessions that expired before the cut-off, nothing else.
        Assert.Equal(1, await Sessions.PurgeAsync(now.AddMinutes(30)));
        Assert.Null(await Sessions.GetAsync(shortLived.Id));
        Assert.NotNull(await Sessions.GetAsync(s1.Id));

        // Cascades: deleting the application, or the user, removes their sessions and hashes.
        var other = await apps.AddAsync(NewApp("blog"));
        var viaApp = New(now, TimeSpan.FromDays(1)) with { AppId = other.Id };
        await Sessions.AddAsync(viaApp, "a1");
        Assert.True(await apps.DeleteAsync(other.Id));
        Assert.Null(await Sessions.GetAsync(viaApp.Id));
        Assert.Null(await Sessions.GetHashesAsync(viaApp.Id));
        Assert.True(await users.DeleteAsync(user.Id));
        Assert.Null(await Sessions.GetAsync(s1.Id));
        Assert.Null(await Sessions.GetHashesAsync(s1.Id));
    }

    [SkippableFact]
    public async Task Audit_is_listed_newest_first_filtered_and_sliced()
    {
        CreateStore();
        var t0 = DateTimeOffset.UtcNow;
        AuditEvent E(int n, string actor, string action) => new(Guid.NewGuid(), t0.AddSeconds(n), actor, action, $"t{n}", n % 2 == 0 ? "success" : "failure", $"d{n}", "127.0.0.1");
        foreach (var e in new[] { E(1, "alice", "x"), E(3, "bob", "y"), E(2, "alice", "y"), E(4, "alice", "x") }) await Audit.AppendAsync(e);

        Assert.Equal(["t4", "t3", "t2", "t1"], (await Audit.ListAsync()).Select(e => e.Target));
        Assert.Equal(["t4", "t1"], (await Audit.ListAsync(actor: "alice", action: "x")).Select(e => e.Target));
        Assert.Equal(["t4", "t3"], (await Audit.ListAsync(take: 2)).Select(e => e.Target));
        var third = (await Audit.ListAsync(take: 2)).Last();
        Assert.Equal(["t2", "t1"], (await Audit.ListAsync(after: new AuditKey(third.At, third.Id))).Select(e => e.Target));
        Assert.Empty(await Audit.ListAsync(actor: "nobody"));
        var first = (await Audit.ListAsync(take: 1)).Single();
        Assert.Equal(("alice", "x", "d4", "127.0.0.1", "success"), (first.Actor, first.Action, first.Detail, first.Address, first.Outcome));
    }

    [SkippableFact]
    public async Task Audit_keyset_pages_have_no_repeats_or_gaps_across_rows_of_one_microsecond()
    {
        CreateStore();
        var t = new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero).AddTicks(10);
        // Ids where .NET's Guid order (first field as a signed int) differs from Postgres uuid order (unsigned bytes).
        var ids = new[]
        {
            "80000000-0000-0000-0000-000000000000", "00000001-0000-0000-0000-000000000000", "7fffffff-ffff-ffff-ffff-ffffffffffff",
            "ffffffff-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000001", "00000000-0100-0000-0000-000000000000",
            "00000000-0000-0100-0000-000000000000", "00000000-0000-0000-0100-000000000000",
        }.Select(Guid.Parse).ToList();
        AuditEvent Ev(Guid id, DateTimeOffset at, string actor = "a") => new(id, at, actor, "act", null, "success", null, null);
        foreach (var id in ids) await Audit.AppendAsync(Ev(id, t));
        var older = Guid.NewGuid();
        var newer = Guid.NewGuid();
        await Audit.AppendAsync(Ev(older, t.AddTicks(-10)));
        await Audit.AppendAsync(Ev(newer, t.AddTicks(10)));

        var expected = new[] { newer }.Concat(ids.OrderBy(i => i.ToString("D"), StringComparer.Ordinal).Reverse()).Append(older).ToList();
        Assert.Equal(expected, (await Audit.ListAsync()).Select(e => e.Id));

        foreach (var size in new[] { 1, 2, 3, 4 })
        {
            var walked = new List<Guid>();
            AuditKey? after = null;
            while (true)
            {
                var page = await Audit.ListAsync(after: after, take: size);
                walked.AddRange(page.Select(e => e.Id));
                if (page.Count < size) break;
                after = new AuditKey(page[^1].At, page[^1].Id);
            }
            Assert.Equal(expected, walked);
        }

        // after is strict, on the exact key: nothing at or above the key comes back, equal time with a smaller id does
        var mid = ids.OrderBy(i => i.ToString("D"), StringComparer.Ordinal).ElementAt(3);
        var below = await Audit.ListAsync(after: new AuditKey(t, mid));
        Assert.Equal(expected.SkipWhile(i => i != mid).Skip(1), below.Select(e => e.Id));
        Assert.DoesNotContain(below, e => e.Id == mid || e.Id == newer);
        Assert.Contains(below, e => e.Id == older);
        // a key in another time zone offset means the same instant
        Assert.Equal(below.Select(e => e.Id), (await Audit.ListAsync(after: new AuditKey(t.ToOffset(TimeSpan.FromHours(5)), mid))).Select(e => e.Id));
    }

    [SkippableFact]
    public async Task Audit_keyset_combines_with_filters_and_new_rows_do_not_shift_pages()
    {
        CreateStore();
        var t0 = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
        AuditEvent Ev(int n, string actor, string action) => new(Guid.NewGuid(), t0.AddSeconds(n), actor, action, $"t{n}", "success", null, null);
        foreach (var n in Enumerable.Range(1, 6)) await Audit.AppendAsync(Ev(n, n % 2 == 0 ? "even" : "odd", n <= 3 ? "lo" : "hi"));
        var firstPage = await Audit.ListAsync(actor: "even", take: 2);
        Assert.Equal(["t6", "t4"], firstPage.Select(e => e.Target));
        await Audit.AppendAsync(Ev(7, "even", "hi")); // arrives between pages
        await Audit.AppendAsync(Ev(8, "odd", "hi"));
        var key = new AuditKey(firstPage[^1].At, firstPage[^1].Id);
        Assert.Equal(["t2"], (await Audit.ListAsync(actor: "even", after: key, take: 5)).Select(e => e.Target));
        Assert.Equal(["t2"], (await Audit.ListAsync(actor: "even", action: "lo", after: key, take: 5)).Select(e => e.Target));
        Assert.Empty(await Audit.ListAsync(actor: "even", action: "hi", after: new AuditKey(t0.AddSeconds(4), Guid.Empty)));
    }

    [SkippableFact]
    public async Task Audit_rows_cannot_be_changed_or_removed_by_the_app_role()
    {
        CreateStore();
        Skip.If(AppConnection is null, "Postgres only.");
        await Audit.AppendAsync(new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "a", "act", null, "success", null, null));
        await using var conn = new Npgsql.NpgsqlConnection(AppConnection);
        await conn.OpenAsync();
        foreach (var sql in new[] { "UPDATE audit_events SET actor = 'x'", "DELETE FROM audit_events", "TRUNCATE audit_events" })
        {
            await using var cmd = new Npgsql.NpgsqlCommand(sql, conn);
            var ex = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Equal("42501", ex.SqlState); // insufficient_privilege, from the missing grant or the trigger
        }
        Assert.Single(await Audit.ListAsync());
    }

    [SkippableFact]
    public async Task Credentials_upsert_read_and_cascade_with_user()
    {
        var (_, _, users) = CreateStore();
        var user = await users.AddAsync(NewUser("alice"));
        Assert.Null(await Credentials.GetHashAsync(user.Id));
        await Credentials.SetAsync(user.Id, "hash-1", DateTimeOffset.UtcNow);
        Assert.Equal("hash-1", await Credentials.GetHashAsync(user.Id));
        await Credentials.SetAsync(user.Id, "hash-2", DateTimeOffset.UtcNow);
        Assert.Equal("hash-2", await Credentials.GetHashAsync(user.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => Credentials.SetAsync(Guid.NewGuid(), "h", DateTimeOffset.UtcNow));
        Assert.True(await users.DeleteAsync(user.Id));
        Assert.Null(await Credentials.GetHashAsync(user.Id));
    }

    [SkippableFact]
    public async Task Cancelled_token_aborts_the_call()
    {
        var (apps, _, _) = CreateStore();
        await apps.AddAsync(NewApp("billing"));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        // In-memory stores finish synchronously; Postgres must observe the token. Either way it must not return stale data silently
        // for a write.
        var ex = await Record.ExceptionAsync(() => apps.AddAsync(NewApp("late"), cts.Token));
        if (ex is not null) Assert.IsAssignableFrom<OperationCanceledException>(ex);
    }

    [SkippableFact]
    public async Task App_roundtrip_update_delete()
    {
        var (apps, _, _) = CreateStore();
        var app = await apps.AddAsync(NewApp("billing"));
        Assert.Equal(app, await apps.GetAsync(app.Id));
        Assert.Single(await apps.ListAsync());
        var renamed = await apps.UpdateAsync(app with { Name = "invoices" });
        Assert.Equal("invoices", renamed!.Name);
        Assert.True(await apps.DeleteAsync(app.Id));
        Assert.False(await apps.DeleteAsync(app.Id));
        Assert.Null(await apps.GetAsync(app.Id));
        Assert.Null(await apps.UpdateAsync(app));
    }

    [SkippableFact]
    public async Task App_names_are_unique_case_insensitively()
    {
        var (apps, _, _) = CreateStore();
        await apps.AddAsync(NewApp("billing"));
        await Assert.ThrowsAsync<ConflictException>(() => apps.AddAsync(NewApp("BILLING")));
        var other = await apps.AddAsync(NewApp("crm"));
        await Assert.ThrowsAsync<ConflictException>(() => apps.UpdateAsync(other with { Name = "billing" }));
        await apps.UpdateAsync(other with { Name = "crm" }); // same name on itself is fine
    }

    [SkippableFact]
    public async Task Role_names_are_unique_per_app_only()
    {
        var (apps, roles, _) = CreateStore();
        var a = await apps.AddAsync(NewApp("a"));
        var b = await apps.AddAsync(NewApp("b"));
        await roles.AddAsync(NewRole(a, "admin"));
        await roles.AddAsync(NewRole(b, "admin"));
        await Assert.ThrowsAsync<ConflictException>(() => roles.AddAsync(NewRole(a, "ADMIN")));
        Assert.Single(await roles.ListByAppAsync(a.Id));
    }

    [SkippableFact]
    public async Task User_username_and_email_are_unique()
    {
        var (_, _, users) = CreateStore();
        await users.AddAsync(NewUser("alice"));
        await Assert.ThrowsAsync<ConflictException>(() => users.AddAsync(NewUser("ALICE", "other@example.com")));
        await Assert.ThrowsAsync<ConflictException>(() => users.AddAsync(NewUser("bob", "Alice@Example.com")));
    }

    [SkippableFact]
    public async Task User_list_filters()
    {
        var (_, _, users) = CreateStore();
        await users.AddAsync(NewUser("alice"));
        var bob = await users.AddAsync(NewUser("bob"));
        await users.UpdateAsync(bob with { IsActive = false });
        Assert.Equal(2, (await users.ListAsync()).Count);
        Assert.Equal(["bob"], (await users.ListAsync(active: false)).Select(u => u.Username));
        Assert.Equal(["alice"], (await users.ListAsync(username: "ALICE")).Select(u => u.Username));
    }

    [SkippableFact]
    public async Task Assign_is_idempotent_and_revoke_reports_presence()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var role = await roles.AddAsync(NewRole(app, "admin"));
        var user = await users.AddAsync(NewUser("alice"));
        await users.AssignRoleAsync(user.Id, role.Id);
        await users.AssignRoleAsync(user.Id, role.Id);
        Assert.Single(await users.ListRolesAsync(user.Id));
        Assert.True(await users.RevokeRoleAsync(user.Id, role.Id));
        Assert.False(await users.RevokeRoleAsync(user.Id, role.Id));
    }

    [SkippableFact]
    public async Task ListRoles_filters_by_app()
    {
        var (apps, roles, users) = CreateStore();
        var a = await apps.AddAsync(NewApp("a"));
        var b = await apps.AddAsync(NewApp("b"));
        var user = await users.AddAsync(NewUser("alice"));
        foreach (var r in new[] { NewRole(a, "x"), NewRole(b, "y") })
        {
            await roles.AddAsync(r);
            await users.AssignRoleAsync(user.Id, r.Id);
        }
        Assert.Equal(2, (await users.ListRolesAsync(user.Id)).Count);
        Assert.Equal(["x"], (await users.ListRolesAsync(user.Id, a.Id)).Select(r => r.Name));
    }

    [SkippableFact]
    public async Task Role_for_missing_app_is_rejected()
    {
        var (_, roles, _) = CreateStore();
        await Assert.ThrowsAsync<NotFoundException>(() => roles.AddAsync(NewRole(NewApp("ghost"), "admin")));
    }

    [SkippableFact]
    public async Task Assignment_for_missing_user_or_role_is_rejected_and_leaves_nothing()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var role = await roles.AddAsync(NewRole(app, "admin"));
        var user = await users.AddAsync(NewUser("alice"));
        await Assert.ThrowsAsync<NotFoundException>(() => users.AssignRoleAsync(Guid.NewGuid(), role.Id));
        await Assert.ThrowsAsync<NotFoundException>(() => users.AssignRoleAsync(user.Id, Guid.NewGuid()));
        Assert.Empty(await users.ListRolesAsync(user.Id));
    }

    [SkippableFact]
    public async Task Parallel_duplicate_creates_yield_exactly_one_winner()
    {
        var (apps, _, _) = CreateStore();
        var results = await Task.WhenAll(Enumerable.Range(0, 30).Select(async _ =>
        {
            try
            {
                await apps.AddAsync(NewApp("same-name"));
                return true;
            }
            catch (ConflictException)
            {
                return false;
            }
        }));
        Assert.Equal(1, results.Count(r => r));
        Assert.Single(await apps.ListAsync());
    }

    [SkippableFact]
    public async Task Creating_role_while_deleting_app_leaves_no_orphan_role()
    {
        var (apps, roles, _) = CreateStore();
        for (var i = 0; i < 40; i++)
        {
            var app = await apps.AddAsync(NewApp($"race-{i}"));
            var role = NewRole(app, "r");
            await Task.WhenAll(
                Swallow(() => roles.AddAsync(role)),
                Swallow(() => apps.DeleteAsync(app.Id)));
            Assert.Empty(await roles.ListByAppAsync(app.Id));
            Assert.Null(await roles.GetAsync(role.Id));
        }
    }

    [SkippableFact]
    public async Task Assigning_while_deleting_role_leaves_no_assignment()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var user = await users.AddAsync(NewUser("alice"));
        for (var i = 0; i < 40; i++)
        {
            var role = await roles.AddAsync(NewRole(app, $"r{i}"));
            await Task.WhenAll(
                Swallow(() => users.AssignRoleAsync(user.Id, role.Id)),
                Swallow(() => roles.DeleteAsync(role.Id)));
            Assert.DoesNotContain(await users.ListRolesAsync(user.Id), r => r.Id == role.Id);
        }
    }

    [SkippableFact]
    public async Task User_timestamps_round_trip()
    {
        var (_, _, users) = CreateStore();
        var created = DateTimeOffset.UtcNow;
        var user = await users.AddAsync(NewUser("alice") with { CreatedAt = created, UpdatedAt = created });
        var read = await users.GetAsync(user.Id);
        Assert.True(Math.Abs((read!.CreatedAt - created).TotalMilliseconds) < 1);
        Assert.Equal(TimeSpan.Zero, read.CreatedAt.Offset);
    }

    // Races may legitimately end in NotFound; anything else is a failure.
    private static async Task Swallow<T>(Func<Task<T>> action)
    {
        try
        {
            await action();
        }
        catch (NotFoundException)
        {
        }
    }

    private static Task Swallow(Func<Task> action) => Swallow(async () =>
    {
        await action();
        return 0;
    });

    [SkippableFact]
    public async Task Deleting_role_user_or_app_removes_assignments()
    {
        var (apps, roles, users) = CreateStore();
        var app = await apps.AddAsync(NewApp("a"));
        var r1 = await roles.AddAsync(NewRole(app, "r1"));
        var r2 = await roles.AddAsync(NewRole(app, "r2"));
        var alice = await users.AddAsync(NewUser("alice"));
        var bob = await users.AddAsync(NewUser("bob"));
        await users.AssignRoleAsync(alice.Id, r1.Id);
        await users.AssignRoleAsync(alice.Id, r2.Id);
        await users.AssignRoleAsync(bob.Id, r1.Id);

        await roles.DeleteAsync(r1.Id);
        Assert.Equal(["r2"], (await users.ListRolesAsync(alice.Id)).Select(r => r.Name));
        Assert.Empty(await users.ListRolesAsync(bob.Id));

        await users.DeleteAsync(alice.Id);
        await apps.DeleteAsync(app.Id);
        Assert.Null(await roles.GetAsync(r2.Id));
        Assert.Empty(await users.ListRolesAsync(bob.Id));
    }
}

public class InMemoryStoreContract : StoreContract
{
    protected override (IAppRepository, IRoleRepository, IUserRepository) CreateStore()
    {
        var s = new InMemoryStore();
        Credentials = new InMemoryCredentialRepository(s);
        Audit = new InMemoryAuditRepository(s);
        Clients = new InMemoryClientRepository(s);
        Sessions = new InMemorySessionRepository(s);
        return (new InMemoryAppRepository(s), new InMemoryRoleRepository(s), new InMemoryUserRepository(s));
    }
}
