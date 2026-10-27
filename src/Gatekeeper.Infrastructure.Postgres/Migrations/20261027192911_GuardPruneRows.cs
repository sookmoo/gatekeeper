using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class GuardPruneRows : Migration
    {
        // Slice 8e, round 3. Rows that look like the prune command's own (actor system:prune, or an action starting audit.prune) can be inserted only
        // when the session user is the table owner, so the serving role cannot forge a prune history. search_path is pinned. Creating the trigger takes
        // a short SHARE ROW EXCLUSIVE lock on audit_events, hence lock_timeout (as in AddVersionTriggers); no data changes.
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql(@"
CREATE FUNCTION audit_events_guard_prune_rows() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.actor = 'system:prune' OR NEW.action LIKE 'audit.prune%')
     AND session_user::text <> (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID) THEN
    RAISE EXCEPTION 'audit.prune rows are written by the prune command only' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION audit_events_guard_prune_rows() FROM PUBLIC;
CREATE TRIGGER audit_events_guard_prune_rows BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_guard_prune_rows();");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("DROP TRIGGER audit_events_guard_prune_rows ON audit_events; DROP FUNCTION audit_events_guard_prune_rows();");
        }
    }
}
