using System.CommandLine;
using System.Text.Json;

namespace Gatekeeper.Cli;

public static class CliApp
{
    public const string DefaultUrl = "http://localhost:5080";

    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    private static class Domain
    {
        public const string AdminApp = "gatekeeper";
    }

    private static readonly string[] AppFields = ["id", "name"];
    private static readonly string[] RoleFields = ["id", "name", "description"];
    private static readonly string[] ClientFields = ["id", "name", "appId", "isActive"];
    private static readonly string[] AuditFields = ["at", "outcome", "actor", "action", "target", "detail"];
    private static readonly string[] UserFields = ["id", "username", "email", "isActive", "displayName"];

    /// <param name="tokens">Where the login token is kept (default: a private file in the user's state directory).</param>
    /// <param name="readSecret">Reads a password without echo (prompt text, whether to ask twice; null at end of input).</param>
    public static async Task<int> RunAsync(
        string[] args, Func<Uri, HttpClient> httpFactory, TextWriter stdout, TextWriter stderr,
        ITokenStore? tokens = null, Func<string, bool, string?>? readSecret = null)
    {
        tokens ??= new FileTokenStore();
        readSecret ??= Secrets.Read;
        var url = new Option<string?>("--url") { Description = $"Gatekeeper base URL (env GATEKEEPER_URL, default {DefaultUrl})", Recursive = true };
        var json = new Option<bool>("--json") { Description = "Print raw JSON", Recursive = true };

        var root = new RootCommand("gk: Gatekeeper command line client") { Options = { url, json } };
        root.Subcommands.Add(AppCommands());
        root.Subcommands.Add(RoleCommands());
        root.Subcommands.Add(UserCommands());
        root.Subcommands.Add(ClientCommands());
        root.Subcommands.Add(AuditCommands());
        root.Subcommands.Add(LoginCommand());
        root.Subcommands.Add(LogoutCommand());

        return await root.Parse(args).InvokeAsync(new InvocationConfiguration { Output = stdout, Error = stderr });

        // ---- helpers capture url/json/streams ----

        // The saved token is sent only to the server it was issued by, never to whatever --url points at.
        string? TokenFor(Uri uri)
        {
            var fromEnv = Environment.GetEnvironmentVariable("GATEKEEPER_TOKEN");
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
            var saved = tokens.Load();
            return saved is not null && saved.ExpiresAt > DateTimeOffset.UtcNow
                   && string.Equals(saved.Origin, uri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase)
                ? saved.AccessToken
                : null;
        }

        Command LoginCommand()
        {
            var user = new Option<string>("--user") { Description = "Username", Required = true };
            var application = new Option<string>("--application") { Description = "Application to sign in to", DefaultValueFactory = _ => Domain.AdminApp };
            return Cmd("login", "Sign in (password from stdin or a hidden prompt) and save the token", c => { c.Options.Add(user); c.Options.Add(application); }, async x =>
            {
                var password = readSecret("Password: ", false) ?? throw new CliException(1, "No password given.");
                var body = await x.Api.PostAsync(ApiClient.LoginPath,
                    new { username = x.Get(user), password, application = x.Get(application) });
                var expires = DateTimeOffset.UtcNow.AddSeconds(body.GetProperty("expiresIn").GetInt32());
                tokens.Save(new StoredToken(x.Origin, body.GetProperty("accessToken").GetString()!, expires, x.Get(user)!));
                x.Message($"logged in as {x.Get(user)} until {expires.ToLocalTime():yyyy-MM-dd HH:mm}");
            });
        }

        Command LogoutCommand() => Cmd("logout", "Forget the saved token", _ => { }, x =>
        {
            tokens.Clear();
            x.Message("logged out");
            return Task.CompletedTask;
        });

        Command Cmd(string name, string description, Action<Command> configure, Func<Ctx, Task> run)
        {
            var c = new Command(name, description);
            configure(c);
            c.SetAction(async (parse, _) =>
            {
                try
                {
                    var baseUrl = parse.GetValue(url) ?? Environment.GetEnvironmentVariable("GATEKEEPER_URL") ?? DefaultUrl;
                    if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
                        || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                        throw new CliException(1, $"Invalid URL '{baseUrl}': expected http:// or https://.");
                    // Logins and tokens must not cross the network in clear text.
                    if (uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback
                        && Environment.GetEnvironmentVariable("GATEKEEPER_ALLOW_INSECURE") != "1")
                        throw new CliException(1, $"Refusing plain http to {uri.Host}: use https:// (or set GATEKEEPER_ALLOW_INSECURE=1 for a trusted network).");
                    await run(new Ctx(parse, new ApiClient(httpFactory(uri), TokenFor(uri)), parse.GetValue(json), stdout, stderr, uri.GetLeftPart(UriPartial.Authority)));
                    return 0;
                }
                catch (CliException ex)
                {
                    await stderr.WriteLineAsync($"error: {ex.Message}");
                    return ex.ExitCode;
                }
                catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException
                                               or FormatException or NotSupportedException)
                {
                    // The server answered with something this client does not understand.
                    await stderr.WriteLineAsync($"error: unexpected response from server ({ex.GetType().Name}).");
                    return 1;
                }
            });
            return c;
        }

        Command AppCommands()
        {
            var cmd = new Command("app", "Manage applications");
            var app = () => new Argument<string>("app") { Description = "Application name or id" };
            var nameArg = new Argument<string>("name");

            cmd.Subcommands.Add(Cmd("create", "Create an application", c => c.Arguments.Add(nameArg), async x =>
                x.Print(await x.Api.PostAsync("/v1/applications", new { name = x.Get(nameArg) }), AppFields, single: true)));
            cmd.Subcommands.Add(Cmd("list", "List applications", _ => { }, async x =>
                x.Print(await x.Api.GetListAsync("/v1/applications"), AppFields)));
            var getApp = app();
            cmd.Subcommands.Add(Cmd("get", "Show an application", c => c.Arguments.Add(getApp), async x =>
                x.Print(await x.Api.GetAsync($"/v1/applications/{await x.ResolveApp(x.Get(getApp)!)}"), AppFields, single: true)));
            var updApp = app();
            var newName = new Option<string>("--name") { Required = true };
            cmd.Subcommands.Add(Cmd("update", "Rename an application", c => { c.Arguments.Add(updApp); c.Options.Add(newName); }, async x =>
            {
                var id = await x.ResolveApp(x.Get(updApp)!);
                x.Print(await x.Api.PatchAsync($"/v1/applications/{id}", new { name = x.Get(newName) }), AppFields, single: true);
            }));
            var delApp = app();
            cmd.Subcommands.Add(Cmd("delete", "Delete an application and its roles", c => c.Arguments.Add(delApp), async x =>
            {
                await x.Api.DeleteAsync($"/v1/applications/{await x.ResolveApp(x.Get(delApp)!)}");
                x.Message("deleted");
            }));
            return cmd;
        }

        Command RoleCommands()
        {
            var cmd = new Command("role", "Manage roles");
            Option<string> AppOpt(bool required) => new("--app") { Description = "Application name or id", Required = required };
            Argument<string> RoleArg() => new("role") { Description = "Role id, or name together with --app" };

            var cName = new Argument<string>("name");
            var cApp = AppOpt(true);
            var cDesc = new Option<string?>("--description");
            cmd.Subcommands.Add(Cmd("create", "Create a role in an application", c => { c.Arguments.Add(cName); c.Options.Add(cApp); c.Options.Add(cDesc); }, async x =>
            {
                var appId = await x.ResolveApp(x.Get(cApp)!);
                x.Print(await x.Api.PostAsync($"/v1/applications/{appId}/roles",
                    new { name = x.Get(cName), description = x.Get(cDesc) }), RoleFields, single: true);
            }));

            var lApp = AppOpt(true);
            cmd.Subcommands.Add(Cmd("list", "List roles of an application", c => c.Options.Add(lApp), async x =>
                x.Print(await x.Api.GetListAsync($"/v1/applications/{await x.ResolveApp(x.Get(lApp)!)}/roles"), RoleFields)));

            var gRole = RoleArg(); var gApp = AppOpt(false);
            cmd.Subcommands.Add(Cmd("get", "Show a role", c => { c.Arguments.Add(gRole); c.Options.Add(gApp); }, async x =>
                x.Print(await x.Api.GetAsync($"/v1/roles/{await x.ResolveRole(x.Get(gRole)!, x.Get(gApp))}"), RoleFields, single: true)));

            var uRole = RoleArg(); var uApp = AppOpt(false);
            var uName = new Option<string?>("--name"); var uDesc = new Option<string?>("--description");
            cmd.Subcommands.Add(Cmd("update", "Update a role", c => { c.Arguments.Add(uRole); c.Options.Add(uApp); c.Options.Add(uName); c.Options.Add(uDesc); }, async x =>
            {
                var id = await x.ResolveRole(x.Get(uRole)!, x.Get(uApp));
                var body = new { name = x.Get(uName), description = x.Get(uDesc) };
                x.Print(await x.Api.PatchAsync($"/v1/roles/{id}", body), RoleFields, single: true);
            }));

            var dRole = RoleArg(); var dApp = AppOpt(false);
            cmd.Subcommands.Add(Cmd("delete", "Delete a role", c => { c.Arguments.Add(dRole); c.Options.Add(dApp); }, async x =>
            {
                await x.Api.DeleteAsync($"/v1/roles/{await x.ResolveRole(x.Get(dRole)!, x.Get(dApp))}");
                x.Message("deleted");
            }));
            return cmd;
        }

        Command ClientCommands()
        {
            var cmd = new Command("client", "Manage service identities (machine clients of an application)");
            Argument<string> ClientArg() => new("client") { Description = "Client name or id" };
            Option<string> AppOpt(bool required) => new("--app") { Description = "Application name or id", Required = required };
            Argument<string> RoleArg() => new("role") { Description = "Role id, or name (it is looked up in the client's application)" };

            var cName = new Argument<string>("name") { Description = "Client name (lowercase slug)" };
            var cApp = AppOpt(true);
            var cInactive = new Option<bool>("--inactive") { Description = "Create it disabled" };
            cmd.Subcommands.Add(Cmd("create", "Create a client; its secret is shown once", c => { c.Arguments.Add(cName); c.Options.Add(cApp); c.Options.Add(cInactive); }, async x =>
            {
                var app = await x.ResolveApp(x.Get(cApp)!);
                var created = await x.Api.PostAsync("/v1/clients", new { name = x.Get(cName), application = app, isActive = !x.Get(cInactive) });
                x.Print(created, [.. ClientFields, "secret"], single: true);
                x.Warn("Store the secret now: it cannot be shown again (rotate to get a new one).");
            }));

            var lApp = new Option<string?>("--app") { Description = "Only clients of this application" };
            cmd.Subcommands.Add(Cmd("list", "List clients", c => c.Options.Add(lApp), async x =>
            {
                var app = x.Get(lApp);
                var query = app is null ? "" : $"?application={await x.ResolveApp(app)}";
                x.Print(await x.Api.GetListAsync("/v1/clients" + query), ClientFields);
            }));

            var gClient = ClientArg();
            cmd.Subcommands.Add(Cmd("get", "Show a client", c => c.Arguments.Add(gClient), async x =>
                x.Print(await x.Api.GetAsync($"/v1/clients/{await x.ResolveClient(x.Get(gClient)!)}"), ClientFields, single: true)));

            var uClient = ClientArg(); var uName = new Option<string?>("--name"); var uActive = new Option<bool?>("--active");
            cmd.Subcommands.Add(Cmd("update", "Rename, enable or disable a client", c => { c.Arguments.Add(uClient); c.Options.Add(uName); c.Options.Add(uActive); }, async x =>
            {
                var id = await x.ResolveClient(x.Get(uClient)!);
                x.Print(await x.Api.PatchAsync($"/v1/clients/{id}", new { name = x.Get(uName), isActive = x.Get(uActive) }), ClientFields, single: true);
            }));

            var rClient = ClientArg();
            cmd.Subcommands.Add(Cmd("rotate-secret", "Issue a new secret; the old one stops working at once", c => c.Arguments.Add(rClient), async x =>
            {
                var id = await x.ResolveClient(x.Get(rClient)!);
                x.Print(await x.Api.PostAsync($"/v1/clients/{id}/secret", new { }), ["secret"], single: true);
                x.Warn("Store the secret now: it cannot be shown again.");
            }));

            var dClient = ClientArg();
            cmd.Subcommands.Add(Cmd("delete", "Delete a client", c => c.Arguments.Add(dClient), async x =>
            {
                await x.Api.DeleteAsync($"/v1/clients/{await x.ResolveClient(x.Get(dClient)!)}");
                x.Message("deleted");
            }));

            var sClient = ClientArg();
            cmd.Subcommands.Add(Cmd("roles", "List a client's roles", c => c.Arguments.Add(sClient), async x =>
                x.Print(await x.Api.GetListAsync($"/v1/clients/{await x.ResolveClient(x.Get(sClient)!)}/roles"), RoleFields)));

            var aClient = ClientArg(); var aRole = RoleArg();
            cmd.Subcommands.Add(Cmd("assign", "Give a client a role of its application", c => { c.Arguments.Add(aClient); c.Arguments.Add(aRole); }, async x =>
            {
                var (client, role) = await x.ResolveClientRole(x.Get(aClient)!, x.Get(aRole)!);
                await x.Api.PutAsync($"/v1/clients/{client}/roles/{role}");
                x.Message("assigned");
            }));

            var vClient = ClientArg(); var vRole = RoleArg();
            cmd.Subcommands.Add(Cmd("revoke", "Take a role away from a client", c => { c.Arguments.Add(vClient); c.Arguments.Add(vRole); }, async x =>
            {
                var (client, role) = await x.ResolveClientRole(x.Get(vClient)!, x.Get(vRole)!);
                await x.Api.DeleteAsync($"/v1/clients/{client}/roles/{role}");
                x.Message("revoked");
            }));
            return cmd;
        }

        Command AuditCommands()
        {
            var cmd = new Command("audit", "Read the audit trail");
            var actor = new Option<string?>("--actor") { Description = "Only events by this actor (user id, or 'anonymous'/'system')" };
            var action = new Option<string?>("--action") { Description = "Only this action, e.g. auth.login or 'PUT /v1/users/{id}/password'" };
            var limit = new Option<int>("--limit") { Description = "How many events, newest first (1-200)", DefaultValueFactory = _ => 50 };
            cmd.Subcommands.Add(Cmd("list", "List recent audit events", c => { c.Options.Add(actor); c.Options.Add(action); c.Options.Add(limit); }, async x =>
            {
                var q = new List<string> { $"limit={x.Get(limit)}" };
                if (x.Get(actor) is { } a) q.Add($"actor={Uri.EscapeDataString(a)}");
                if (x.Get(action) is { } act) q.Add($"action={Uri.EscapeDataString(act)}");
                var page = await x.Api.GetAsync("/v1/audit?" + string.Join('&', q));
                x.Print(page.GetProperty("items"), AuditFields);
            }));
            return cmd;
        }

        Command UserCommands()
        {
            var cmd = new Command("user", "Manage users and their roles");
            Argument<string> UserArg() => new("user") { Description = "Username or id" };
            Argument<string> RoleArg() => new("role") { Description = "Role id, or name together with --app" };
            Option<string?> AppOpt() => new("--app") { Description = "Application name or id" };

            var cUser = new Argument<string>("username");
            var cEmail = new Option<string>("--email") { Required = true };
            var cDisplay = new Option<string?>("--display-name");
            var cInactive = new Option<bool>("--inactive") { Description = "Create the user disabled" };
            cmd.Subcommands.Add(Cmd("create", "Create a user", c => { c.Arguments.Add(cUser); c.Options.Add(cEmail); c.Options.Add(cDisplay); c.Options.Add(cInactive); }, async x =>
                x.Print(await x.Api.PostAsync("/v1/users", new
                {
                    username = x.Get(cUser),
                    email = x.Get(cEmail),
                    displayName = x.Get(cDisplay),
                    isActive = !x.Get(cInactive),
                }), UserFields, single: true)));

            var lActive = new Option<bool?>("--active") { Description = "Filter by active state (true/false)" };
            cmd.Subcommands.Add(Cmd("list", "List users", c => c.Options.Add(lActive), async x =>
            {
                var active = x.Get(lActive);
                x.Print(await x.Api.GetListAsync(active is null ? "/v1/users" : $"/v1/users?active={active.ToString()!.ToLowerInvariant()}"), UserFields);
            }));

            var gUser = UserArg();
            cmd.Subcommands.Add(Cmd("get", "Show a user", c => c.Arguments.Add(gUser), async x =>
                x.Print(await x.Api.GetAsync($"/v1/users/{await x.ResolveUser(x.Get(gUser)!)}"), UserFields, single: true)));

            var uUser = UserArg();
            var uName = new Option<string?>("--username"); var uEmail = new Option<string?>("--email");
            var uDisplay = new Option<string?>("--display-name"); var uActive = new Option<bool?>("--active");
            cmd.Subcommands.Add(Cmd("update", "Update a user", c => { c.Arguments.Add(uUser); c.Options.Add(uName); c.Options.Add(uEmail); c.Options.Add(uDisplay); c.Options.Add(uActive); }, async x =>
            {
                var id = await x.ResolveUser(x.Get(uUser)!);
                var body = new { username = x.Get(uName), email = x.Get(uEmail), displayName = x.Get(uDisplay), isActive = x.Get(uActive) };
                x.Print(await x.Api.PatchAsync($"/v1/users/{id}", body), UserFields, single: true);
            }));

            var pUser = UserArg();
            cmd.Subcommands.Add(Cmd("set-password", "Set a user's password (read from stdin or a hidden prompt)", c => c.Arguments.Add(pUser), async x =>
            {
                var id = await x.ResolveUser(x.Get(pUser)!);
                var password = readSecret("New password: ", true) ?? throw new CliException(1, "No password given.");
                await x.Api.PutAsync($"/v1/users/{id}/password", new { password });
                x.Message("password set");
            }));

            var dUser = UserArg();
            cmd.Subcommands.Add(Cmd("delete", "Delete a user", c => c.Arguments.Add(dUser), async x =>
            {
                await x.Api.DeleteAsync($"/v1/users/{await x.ResolveUser(x.Get(dUser)!)}");
                x.Message("deleted");
            }));

            var rUser = UserArg(); var rApp = AppOpt();
            cmd.Subcommands.Add(Cmd("roles", "List a user's roles", c => { c.Arguments.Add(rUser); c.Options.Add(rApp); }, async x =>
            {
                var id = await x.ResolveUser(x.Get(rUser)!);
                var app = x.Get(rApp);
                var query = app is null ? "" : $"?application={await x.ResolveApp(app)}";
                x.Print(await x.Api.GetListAsync($"/v1/users/{id}/roles{query}"), RoleFields);
            }));

            var aUser = UserArg(); var aRole = RoleArg(); var aApp = AppOpt();
            cmd.Subcommands.Add(Cmd("assign", "Assign a role to a user", c => { c.Arguments.Add(aUser); c.Arguments.Add(aRole); c.Options.Add(aApp); }, async x =>
            {
                var user = await x.ResolveUser(x.Get(aUser)!);
                var role = await x.ResolveRole(x.Get(aRole)!, x.Get(aApp));
                await x.Api.PutAsync($"/v1/users/{user}/roles/{role}");
                x.Message("assigned");
            }));

            var vUser = UserArg(); var vRole = RoleArg(); var vApp = AppOpt();
            cmd.Subcommands.Add(Cmd("revoke", "Revoke a role from a user", c => { c.Arguments.Add(vUser); c.Arguments.Add(vRole); c.Options.Add(vApp); }, async x =>
            {
                var user = await x.ResolveUser(x.Get(vUser)!);
                var role = await x.ResolveRole(x.Get(vRole)!, x.Get(vApp));
                await x.Api.DeleteAsync($"/v1/users/{user}/roles/{role}");
                x.Message("revoked");
            }));
            return cmd;
        }
    }

    private sealed class Ctx(ParseResult parse, ApiClient api, bool json, TextWriter stdout, TextWriter stderr, string origin)
    {
        public string Origin { get; } = origin;

        public ApiClient Api { get; } = api;

        public T? Get<T>(Argument<T> a) => parse.GetValue(a);

        public T? Get<T>(Option<T> o) => parse.GetValue(o);

        /// <summary>A hint for the person at the terminal; stderr keeps stdout clean for scripts.</summary>
        public void Warn(string text) { if (!json) stderr.WriteLine(text); }

        public void Message(string text)
        {
            if (json) stdout.WriteLine(JsonSerializer.Serialize(new { result = text }));
            else stdout.WriteLine(text);
        }

        public void Print(JsonElement body, string[] fields, bool single = false)
        {
            if (json)
            {
                stdout.WriteLine(JsonSerializer.Serialize(body, Pretty));
                return;
            }
            if (body.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in body.EnumerateArray()) stdout.WriteLine(Row(item, fields));
                return;
            }
            if (single)
                foreach (var f in fields) stdout.WriteLine($"{f}: {Value(body, f)}");
        }

        private static string Row(JsonElement item, string[] fields) =>
            string.Join("  ", fields.Select(f => Value(item, f)));

        private static string Value(JsonElement item, string field) =>
            item.TryGetProperty(field, out var v)
                ? v.ValueKind switch
                {
                    JsonValueKind.String => Safe.Text(v.GetString()),
                    JsonValueKind.Null => "",
                    _ => Safe.Text(v.ToString()),
                }
                : "";

        public async Task<Guid> ResolveApp(string app)
        {
            if (Guid.TryParse(app, out var id)) return id;
            var all = await Api.GetListAsync("/v1/applications");
            var match = all.EnumerateArray().FirstOrDefault(a =>
                string.Equals(a.GetProperty("name").GetString(), app, StringComparison.OrdinalIgnoreCase));
            return match.ValueKind == JsonValueKind.Undefined
                ? throw new CliException(2, $"Application '{app}' not found.")
                : match.GetProperty("id").GetGuid();
        }

        public async Task<Guid> ResolveUser(string user)
        {
            if (Guid.TryParse(user, out var id)) return id;
            var found = await Api.GetListAsync($"/v1/users?username={Uri.EscapeDataString(user)}");
            return found.GetArrayLength() == 0
                ? throw new CliException(2, $"User '{user}' not found.")
                : found[0].GetProperty("id").GetGuid();
        }

        public async Task<Guid> ResolveClient(string client)
        {
            if (Guid.TryParse(client, out var id)) return id;
            var all = await Api.GetListAsync("/v1/clients");
            var match = all.EnumerateArray().FirstOrDefault(c =>
                string.Equals(c.GetProperty("name").GetString(), client, StringComparison.OrdinalIgnoreCase));
            return match.ValueKind == JsonValueKind.Undefined
                ? throw new CliException(2, $"Client '{client}' not found.")
                : match.GetProperty("id").GetGuid();
        }

        /// <summary>A role name is looked up in the client's own application (a client can only hold those roles).</summary>
        public async Task<(Guid Client, Guid Role)> ResolveClientRole(string client, string role)
        {
            var clientId = await ResolveClient(client);
            if (Guid.TryParse(role, out var roleId)) return (clientId, roleId);
            var appId = (await Api.GetAsync($"/v1/clients/{clientId}")).GetProperty("appId").GetGuid();
            var roles = await Api.GetListAsync($"/v1/applications/{appId}/roles");
            var match = roles.EnumerateArray().FirstOrDefault(r =>
                string.Equals(r.GetProperty("name").GetString(), role, StringComparison.OrdinalIgnoreCase));
            return match.ValueKind == JsonValueKind.Undefined
                ? throw new CliException(2, $"Role '{role}' not found in the client's application.")
                : (clientId, match.GetProperty("id").GetGuid());
        }

        public async Task<Guid> ResolveRole(string role, string? app)
        {
            if (Guid.TryParse(role, out var id)) return id;
            if (app is null) throw new CliException(1, $"Role '{role}' is a name; pass --app <application> or use the role id.");
            var appId = await ResolveApp(app);
            var roles = await Api.GetListAsync($"/v1/applications/{appId}/roles");
            var match = roles.EnumerateArray().FirstOrDefault(r =>
                string.Equals(r.GetProperty("name").GetString(), role, StringComparison.OrdinalIgnoreCase));
            return match.ValueKind == JsonValueKind.Undefined
                ? throw new CliException(2, $"Role '{role}' not found in application '{app}'.")
                : match.GetProperty("id").GetGuid();
        }
    }
}
