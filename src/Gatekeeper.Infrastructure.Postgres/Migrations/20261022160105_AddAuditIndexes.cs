using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditIndexes : Migration
    {
        // CREATE INDEX CONCURRENTLY does not block audit writes on a large table, but cannot run in a transaction and
        // leaves an INVALID index behind if it fails or is cancelled. So an invalid leftover of the same name is dropped
        // first, and an index that already exists and is valid (for example pre-created by an operator) is kept.
        private static string DropInvalid(string name) => $@"
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
             WHERE c.relname = '{name}' AND c.relnamespace = 'public'::regnamespace AND NOT i.indisvalid) THEN
    DROP INDEX public.{name};
  END IF;
END $$;";

        // One statement per call: CONCURRENTLY is refused inside a multi-statement batch (an implicit transaction).
        private static string Create(string name, string column) =>
            $"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON audit_events ({column}, at DESC, id DESC)";

        private static void Add(MigrationBuilder b, string name, string column)
        {
            b.Sql(DropInvalid(name), suppressTransaction: true);
            b.Sql(Create(name, column), suppressTransaction: true);
        }

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            Add(migrationBuilder, "ix_audit_events_action_at_id", "action");
            Add(migrationBuilder, "ix_audit_events_actor_at_id", "actor");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_audit_events_action_at_id",
                table: "audit_events");

            migrationBuilder.DropIndex(
                name: "ix_audit_events_actor_at_id",
                table: "audit_events");
        }
    }
}
