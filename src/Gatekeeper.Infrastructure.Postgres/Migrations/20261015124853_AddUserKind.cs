using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gatekeeper.Infrastructure.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddUserKind : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "expires_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "kind",
                table: "users",
                type: "character varying(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "person");

            migrationBuilder.AddCheckConstraint(
                name: "ck_users_kind",
                table: "users",
                sql: "kind IN ('person', 'test', 'shared')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_users_test_expires",
                table: "users",
                sql: "(kind = 'test') = (expires_at IS NOT NULL)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_users_kind",
                table: "users");

            migrationBuilder.DropCheckConstraint(
                name: "ck_users_test_expires",
                table: "users");

            migrationBuilder.DropColumn(
                name: "expires_at",
                table: "users");

            migrationBuilder.DropColumn(
                name: "kind",
                table: "users");
        }
    }
}
