using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnerableIssuerAPI.Migrations
{
    /// <inheritdoc />
    public partial class change_pwd_reset : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ExpireAt",
                table: "PasswordResetTokens",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<bool>(
                name: "IsUsed",
                table: "PasswordResetTokens",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExpireAt",
                table: "PasswordResetTokens");

            migrationBuilder.DropColumn(
                name: "IsUsed",
                table: "PasswordResetTokens");
        }
    }
}
