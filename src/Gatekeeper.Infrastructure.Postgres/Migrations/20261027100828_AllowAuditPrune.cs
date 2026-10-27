using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AllowAuditPrune : Migration
    {
        // Slice 8e. audit_events stays append-only for everyone except one path: a DELETE passes only when the session AND the current role
        // is the table's owner AND the transaction has set gatekeeper.audit_prune = 'on' (SET LOCAL, as `prune-audit` does). Any role can set
        // that setting, so the owner test is what matters; the app role has no DELETE privilege and fails the owner test as well. UPDATE and
        // TRUNCATE are refused for everyone, and so is deleting a row written by the prune command itself (actor system:prune): the trail of prunes is permanent. No table is touched (CREATE OR REPLACE FUNCTION takes no table lock), so audit writes are not blocked.
        // search_path is pinned so a caller cannot shadow the functions used here.
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' AND TG_LEVEL = 'ROW'
     AND OLD.actor <> 'system:prune'
     AND session_user::text = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID)
     AND current_user::text = session_user::text
     AND current_setting('gatekeeper.audit_prune', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;");
        }
    }
}
