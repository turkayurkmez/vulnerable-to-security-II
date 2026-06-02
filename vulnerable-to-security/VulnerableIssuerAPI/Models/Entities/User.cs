namespace VulnerableIssuerAPI.Models.Entities;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    // AÇIK: MD5 hash (PCI DSS ihlali — bcrypt/Argon2 kullanılmalı)
    // CVSS: 6.5 (Medium) — Weak Password Hashing
    // PCI DSS: Requirement 8.2.1 — strong cryptography zorunlu
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    // AÇIK: Role string olarak saklanıyor, manipülasyona açık
    // EXPLOIT: JWT payload'daki role claim'i decode edilip değiştirilebilir
    public string Role { get; set; } = "customer"; // "customer", "merchant", "admin"
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    // AÇIK: Güvenlik sorusu cevabı plaintext saklanıyor
    // EXPLOIT: DB dump alındığında tüm güvenlik soruları açıkta
    public string? SecurityAnswer { get; set; }

    public ICollection<Card> Cards { get; set; } = new List<Card>();
    public ICollection<OtpRecord> OtpRecords { get; set; } = new List<OtpRecord>();
    public ICollection<PasswordResetToken> PasswordResetTokens { get; set; } = new List<PasswordResetToken>();
}
