using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionCutoff : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // One transaction. Take both exclusive locks together, up front, under one short timeout: it gives up cleanly (and rolls back)
            // instead of queueing behind a long query. Run the migration again at a quiet moment.
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("LOCK TABLE users, sessions IN ACCESS EXCLUSIVE MODE");

            // No cut-off exists yet (NULL): nobody's existing sessions are affected by this migration.
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "sessions_valid_after",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            // Existing sessions get created_at as the moment their sign-in began (the best the data knows), then the column becomes NOT NULL.
            // The code always writes it, so an old instance that inserts a session without it fails loudly instead of creating a session
            // the cut-off cannot judge: old and new instances must not run side by side across this migration.
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "authenticated_at",
                table: "sessions",
                type: "timestamp with time zone",
                nullable: true);
            migrationBuilder.Sql("UPDATE sessions SET authenticated_at = created_at");
            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "authenticated_at",
                table: "sessions",
                type: "timestamp with time zone",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "timestamp with time zone",
                oldNullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("LOCK TABLE users, sessions IN ACCESS EXCLUSIVE MODE");

            // Without the columns the code of the previous version cannot tell that the cut-off was ending these sessions: end them for real first,
            // or they would come back to life.
            migrationBuilder.Sql(
                "UPDATE sessions SET revoked_at = now() FROM users " +
                "WHERE users.id = sessions.user_id AND users.sessions_valid_after IS NOT NULL " +
                "AND sessions.authenticated_at <= users.sessions_valid_after AND sessions.revoked_at IS NULL");

            migrationBuilder.DropColumn(
                name: "sessions_valid_after",
                table: "users");

            migrationBuilder.DropColumn(
                name: "authenticated_at",
                table: "sessions");
        }
    }
}
