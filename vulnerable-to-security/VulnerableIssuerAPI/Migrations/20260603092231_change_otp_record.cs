using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnerableIssuerAPI.Migrations
{
    /// <inheritdoc />
    public partial class change_otp_record : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ExpiryDate",
                table: "OtpRecords",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<bool>(
                name: "IsUsed",
                table: "OtpRecords",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExpiryDate",
                table: "OtpRecords");

            migrationBuilder.DropColumn(
                name: "IsUsed",
                table: "OtpRecords");
        }
    }
}
