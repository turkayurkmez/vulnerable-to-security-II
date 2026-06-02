using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Data;

public class VulnerableDbContext : DbContext
{
    public VulnerableDbContext(DbContextOptions<VulnerableDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Card> Cards => Set<Card>();
    public DbSet<Transaction> Transactions => Set<Transaction>();
    public DbSet<OtpRecord> OtpRecords => Set<OtpRecord>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Password).IsRequired();
            entity.Property(e => e.Email).IsRequired();
            entity.HasIndex(e => e.Username).IsUnique();
        });

        modelBuilder.Entity<Card>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.CardNumber).IsRequired();
            entity.Property(e => e.CVV).IsRequired();
            entity.HasOne(e => e.User)
                  .WithMany(u => u.Cards)
                  .HasForeignKey(e => e.UserId);
        });

        modelBuilder.Entity<Transaction>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.TransactionId).IsRequired();
            entity.Property(e => e.Amount).HasColumnType("decimal(18,2)");
            entity.HasOne(e => e.Card)
                  .WithMany(c => c.Transactions)
                  .HasForeignKey(e => e.CardId);
        });

        modelBuilder.Entity<OtpRecord>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasOne(e => e.User)
                  .WithMany(u => u.OtpRecords)
                  .HasForeignKey(e => e.UserId);
        });

        modelBuilder.Entity<PasswordResetToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasOne(e => e.User)
                  .WithMany(u => u.PasswordResetTokens)
                  .HasForeignKey(e => e.UserId);
        });
    }
}
