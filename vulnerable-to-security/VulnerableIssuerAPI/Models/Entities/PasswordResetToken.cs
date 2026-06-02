namespace VulnerableIssuerAPI.Models.Entities;

public class PasswordResetToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    // AÇIK: userId + timestamp birleştirilerek üretilen tahmin edilebilir token
    // EXPLOIT: UserId bilinen bir kullanıcı için token tahmin edilebilir
    // Format: "{userId}_{DateTime.Now.Ticks}" — örnek: "1_638500000000000"
    // CVSS: 7.5 (High) — Weak Token Generation
    public string Token { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    // AÇIK: ExpiresAt yok — token sonsuza kadar geçerli
    // EXPLOIT: 6 ay önce üretilen token hâlâ çalışıyor
    // AÇIK: IsUsed yok — token birden fazla kez kullanılabilir (replay attack)
    // EXPLOIT: Şifre değiştirildikten sonra aynı token ile tekrar değiştirilebilir

    public User User { get; set; } = null!;
}
