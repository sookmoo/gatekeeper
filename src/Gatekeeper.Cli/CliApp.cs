using System.CommandLine;
using System.Text.Json;

namespace Gatekeeper.Cli;

public static class CliApp
{
    public const string DefaultUrl = "http://localhost:5080";

    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    private static readonly string[] AppFields = ["id", "name"];
    private static readonly string[] RoleFields = ["id", "name", "description"];
    private static readonly string[] UserFields = ["id", "username", "email", "isActive", "displayName"];

    public static async Task<int> RunAsync(
        string[] args, Func<Uri, HttpClient> httpFactory, TextWriter stdout, TextWriter stderr)
    {
        var url = new Option<string?>("--url") { Description = $"Gatekeeper base URL (env GATEKEEPER_URL, default {DefaultUrl})", Recursive = true };
        var json = new Option<bool>("--json") { Description = "Print raw JSON", Recursive = true };

        var root = new RootCommand("gk: Gatekeeper command line client") { Options = { url, json } };
        root.Subcommands.Add(AppCommands());
        root.Subcommands.Add(RoleCommands());
        root.Subcommands.Add(UserCommands());

        return await root.Parse(args).InvokeAsync(new InvocationConfiguration { Output = stdout, Error = stderr });

        // ---- helpers capture url/json/streams ----

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
                    await run(new Ctx(parse, new ApiClient(httpFactory(uri)), parse.GetValue(json), stdout));
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
                x.Print(await x.Api.GetAsync("/v1/applications"), AppFields)));
            var getApp = app();
            cmd.Subcommands.Add(Cmd("get", "Show an application", c => c.Arguments.Add(getApp), async x =>
                x.Print(await x.Api.GetAsync($"/v1/applications/{await x.ResolveApp(x.Get(getApp)!)}"), AppFields, single: true)));
            var updApp = app();
            var newName = new Option<string>("--name") { Required = true };
            cmd.Subcommands.Add(Cmd("update", "Rename an application", c => { c.Arguments.Add(updApp); c.Options.Add(newName); }, async x =>
            {
                var id = await x.ResolveApp(x.Get(updApp)!);
                x.Print(await x.Api.PutAsync($"/v1/applications/{id}", new { name = x.Get(newName) }), AppFields, single: true);
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
                x.Print(await x.Api.GetAsync($"/v1/applications/{await x.ResolveApp(x.Get(lApp)!)}/roles"), RoleFields)));

            var gRole = RoleArg(); var gApp = AppOpt(false);
            cmd.Subcommands.Add(Cmd("get", "Show a role", c => { c.Arguments.Add(gRole); c.Options.Add(gApp); }, async x =>
                x.Print(await x.Api.GetAsync($"/v1/roles/{await x.ResolveRole(x.Get(gRole)!, x.Get(gApp))}"), RoleFields, single: true)));

            var uRole = RoleArg(); var uApp = AppOpt(false);
            var uName = new Option<string?>("--name"); var uDesc = new Option<string?>("--description");
            cmd.Subcommands.Add(Cmd("update", "Update a role", c => { c.Arguments.Add(uRole); c.Options.Add(uApp); c.Options.Add(uName); c.Options.Add(uDesc); }, async x =>
            {
                var id = await x.ResolveRole(x.Get(uRole)!, x.Get(uApp));
                var current = await x.Api.GetAsync($"/v1/roles/{id}");
                var body = new
                {
                    name = x.Get(uName) ?? current.GetProperty("name").GetString(),
                    description = x.Get(uDesc) ?? current.GetProperty("description").GetString(),
                };
                x.Print(await x.Api.PutAsync($"/v1/roles/{id}", body), RoleFields, single: true);
            }));

            var dRole = RoleArg(); var dApp = AppOpt(false);
            cmd.Subcommands.Add(Cmd("delete", "Delete a role", c => { c.Arguments.Add(dRole); c.Options.Add(dApp); }, async x =>
            {
                await x.Api.DeleteAsync($"/v1/roles/{await x.ResolveRole(x.Get(dRole)!, x.Get(dApp))}");
                x.Message("deleted");
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
                x.Print(await x.Api.GetAsync(active is null ? "/v1/users" : $"/v1/users?active={active.ToString()!.ToLowerInvariant()}"), UserFields);
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
                var cur = await x.Api.GetAsync($"/v1/users/{id}");
                var body = new
                {
                    username = x.Get(uName) ?? cur.GetProperty("username").GetString(),
                    email = x.Get(uEmail) ?? cur.GetProperty("email").GetString(),
                    displayName = x.Get(uDisplay) ?? cur.GetProperty("displayName").GetString(),
                    isActive = x.Get(uActive) ?? cur.GetProperty("isActive").GetBoolean(),
                };
                x.Print(await x.Api.PutAsync($"/v1/users/{id}", body), UserFields, single: true);
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
                x.Print(await x.Api.GetAsync($"/v1/users/{id}/roles{query}"), RoleFields);
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

    private sealed class Ctx(ParseResult parse, ApiClient api, bool json, TextWriter stdout)
    {
        public ApiClient Api { get; } = api;

        public T? Get<T>(Argument<T> a) => parse.GetValue(a);

        public T? Get<T>(Option<T> o) => parse.GetValue(o);

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
                    JsonValueKind.String => v.GetString() ?? "",
                    JsonValueKind.Null => "",
                    _ => v.ToString(),
                }
                : "";

        public async Task<Guid> ResolveApp(string app)
        {
            if (Guid.TryParse(app, out var id)) return id;
            var all = await Api.GetAsync("/v1/applications");
            var match = all.EnumerateArray().FirstOrDefault(a =>
                string.Equals(a.GetProperty("name").GetString(), app, StringComparison.OrdinalIgnoreCase));
            return match.ValueKind == JsonValueKind.Undefined
                ? throw new CliException(2, $"Application '{app}' not found.")
                : match.GetProperty("id").GetGuid();
        }

        public async Task<Guid> ResolveUser(string user)
        {
            if (Guid.TryParse(user, out var id)) return id;
            var found = await Api.GetAsync($"/v1/users?username={Uri.EscapeDataString(user)}");
            return found.GetArrayLength() == 0
                ? throw new CliException(2, $"User '{user}' not found.")
                : found[0].GetProperty("id").GetGuid();
        }

        public async Task<Guid> ResolveRole(string role, string? app)
        {
            if (Guid.TryParse(role, out var id)) return id;
            if (app is null) throw new CliException(1, $"Role '{role}' is a name; pass --app <application> or use the role id.");
            var appId = await ResolveApp(app);
            var roles = await Api.GetAsync($"/v1/applications/{appId}/roles");
            var match = roles.EnumerateArray().FirstOrDefault(r =>
                string.Equals(r.GetProperty("name").GetString(), role, StringComparison.OrdinalIgnoreCase));
            return match.ValueKind == JsonValueKind.Undefined
                ? throw new CliException(2, $"Role '{role}' not found in application '{app}'.")
                : match.GetProperty("id").GetGuid();
        }
    }
}
