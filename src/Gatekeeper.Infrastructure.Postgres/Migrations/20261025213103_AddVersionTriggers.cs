using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddVersionTriggers : Migration
    {
        // The version-bumping own columns of each table (Q6d-3): everything the API lets a caller set. Left out on purpose: users.sessions_valid_after
        // (the session cut-off belongs to sessions, a separate resource) and updated_at (a timestamp, not a value). Credentials, secrets, role links and
        // sessions live in other tables. citext columns are compared as text, so a rename that only changes the case still counts.
        private static readonly (string Table, string[] Columns)[] Tables =
        [
            ("apps", ["name::text"]),
            ("roles", ["app_id", "name::text", "description"]),
            ("users", ["username::text", "email::text", "display_name", "is_active", "created_at", "kind", "expires_at"]),
            ("clients", ["name::text", "app_id", "is_active", "created_at"]),
        ];

        private static string Compare(string column, string left, string right)
        {
            var name = column.Replace("::text", "");
            var cast = column.EndsWith("::text") ? "::text" : "";
            return $"{left}.{name}{cast} IS DISTINCT FROM {right}.{name}{cast}";
        }

        // Always OLD.version + 1, never NEW.version + 1: the application already writes loaded + 1 (and EF's tracked value matches), so adding
        // to NEW.version would bump twice. A writer that changes the version itself counts as a change (an identical PUT still bumps once).
        private static string Function((string Table, string[] Columns) t) => $@"
CREATE FUNCTION {t.Table}_bump_version() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.version IS DISTINCT FROM OLD.version
     OR {string.Join("\n     OR ", t.Columns.Select(c => Compare(c, "NEW", "OLD")))} THEN
    NEW.version := OLD.version + 1;
  ELSE
    NEW.version := OLD.version;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER {t.Table}_bump_version BEFORE UPDATE ON {t.Table}
  FOR EACH ROW EXECUTE FUNCTION {t.Table}_bump_version();
REVOKE EXECUTE ON FUNCTION {t.Table}_bump_version() FROM PUBLIC;

-- A new row always starts at version 1: an INSERT cannot choose a version (a huge one would make the row unupdatable, and delete + re-insert
-- with an old one would make a stale If-Match succeed). An upsert that takes its UPDATE branch is an update and bumps as above.
CREATE FUNCTION {t.Table}_start_version() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  NEW.version := 1;
  RETURN NEW;
END $$;
CREATE TRIGGER {t.Table}_start_version BEFORE INSERT ON {t.Table}
  FOR EACH ROW EXECUTE FUNCTION {t.Table}_start_version();
REVOKE EXECUTE ON FUNCTION {t.Table}_start_version() FROM PUBLIC;";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // One transaction. Take the locks of all four tables together, up front, under one short timeout: it gives up cleanly (and rolls back)
            // instead of queueing behind a long query. Run the migration again at a quiet moment. No data changes, so it is safe on populated tables.
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("LOCK TABLE users, roles, clients, apps IN ACCESS EXCLUSIVE MODE");
            foreach (var t in Tables) migrationBuilder.Sql(Function(t));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("LOCK TABLE users, roles, clients, apps IN ACCESS EXCLUSIVE MODE");
            foreach (var (table, _) in Tables)
            {
                migrationBuilder.Sql($"DROP TRIGGER {table}_bump_version ON {table}");
                migrationBuilder.Sql($"DROP FUNCTION {table}_bump_version()");
                migrationBuilder.Sql($"DROP TRIGGER {table}_start_version ON {table}");
                migrationBuilder.Sql($"DROP FUNCTION {table}_start_version()");
            }
        }
    }
}
