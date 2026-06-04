namespace VulnerableIssuerAPI.Models.Entities;

public class OtpRecord
{
    public int Id { get; set; }
    public int UserId { get; set; }
    // AÇIK: 4 haneli OTP = sadece 10.000 kombinasyon (brute-force trivial)
    // AÇIK: Cryptographically secure random değil, System.Random kullanılıyor
    // EXPLOIT: 0000-9999 arası döngü ile dakikalar içinde kırılabilir
    // CVSS: 8.6 (High) — Insufficient Entropy + Missing Rate Limiting
    public string OtpCode { get; set; } = string.Empty;
    public string Purpose { get; set; } = "login"; // "login", "transaction", "reset"
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    // AÇIK: ExpiresAt yok — OTP sonsuza kadar geçerli
    // EXPLOIT: 1 yıl önce üretilen OTP hâlâ çalışıyor
    // AÇIK: IsUsed yok — aynı OTP defalarca kullanılabilir (replay attack)
    // EXPLOIT: Doğrulanmış OTP tekrar gönderilebilir
    // AÇIK: AttemptCount yok — sınırsız deneme hakkı var
    // EXPLOIT: Brute-force ile tüm kombinasyonlar denenebilir

    public bool IsUsed { get; set; }
    public DateTime ExpiryDate { get; set; }

    public User User { get; set; } = null!;
}
