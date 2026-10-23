using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddVersions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The migration runs in one transaction. Take the exclusive locks of all four tables together, up front, under one short
            // timeout: it gives up cleanly (and rolls back) instead of queueing behind a long query, which would make every other query
            // on the table wait behind this one. Run the migration again at a quiet moment.
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("LOCK TABLE users, roles, clients, apps IN ACCESS EXCLUSIVE MODE");

            migrationBuilder.AddColumn<long>(
                name: "version",
                table: "users",
                type: "bigint",
                nullable: false,
                defaultValue: 1L);

            migrationBuilder.AddColumn<long>(
                name: "version",
                table: "roles",
                type: "bigint",
                nullable: false,
                defaultValue: 1L);

            migrationBuilder.AddColumn<long>(
                name: "version",
                table: "clients",
                type: "bigint",
                nullable: false,
                defaultValue: 1L);

            migrationBuilder.AddColumn<long>(
                name: "version",
                table: "apps",
                type: "bigint",
                nullable: false,
                defaultValue: 1L);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("SET LOCAL lock_timeout = '2s'");
            migrationBuilder.Sql("LOCK TABLE users, roles, clients, apps IN ACCESS EXCLUSIVE MODE");

            migrationBuilder.DropColumn(
                name: "version",
                table: "users");

            migrationBuilder.DropColumn(
                name: "version",
                table: "roles");

            migrationBuilder.DropColumn(
                name: "version",
                table: "clients");

            migrationBuilder.DropColumn(
                name: "version",
                table: "apps");
        }
    }
}
