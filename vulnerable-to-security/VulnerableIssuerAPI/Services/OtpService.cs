using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class OtpService
{
    private readonly VulnerableDbContext _context;

    public OtpService(VulnerableDbContext context)
    {
        _context = context;
    }

    public async Task<string> GenerateOtpAsync(int userId, string purpose)
    {
        // AÇIK: System.Random — cryptographically secure değil
        // Güvenli alternatif: RandomNumberGenerator.GetInt32(100000, 999999)
        // AÇIK: 4 haneli = 10.000 kombinasyon — brute-force trivial
        // Güvenli alternatif: 6+ haneli TOTP (RFC 6238)
        // CVSS: 8.6 (High) — Insufficient Entropy
        // Modül 2.2 (OTP Güvenliği) için
        var random = new Random();
        var otpCode = random.Next(1000, 9999).ToString();

        // AÇIK: Önceki OTP'ler silinmiyor — tüm geçmiş OTP'ler hâlâ geçerli
        // AÇIK: Rate limiting kontrolü yapılmıyor (bu servis katmanında da olmaz)
        var otpRecord = new OtpRecord
        {
            UserId = userId,
            OtpCode = otpCode,
            Purpose = purpose,
            CreatedAt = DateTime.UtcNow
            // AÇIK: ExpiresAt set edilmiyor — OTP sonsuza kadar geçerli
            // AÇIK: IsUsed flag yok — replay attack mümkün
        };

        _context.OtpRecords.Add(otpRecord);
        await _context.SaveChangesAsync();

        // AÇIK: OTP kodu log'a yazılıyor (log injection riski + sensitive data exposure)
        // EXPLOIT: Log dosyasına erişen kişi tüm OTP'leri görebilir
        Console.WriteLine($"[DEBUG] OTP generated for userId={userId}: {otpCode}");

        // AÇIK: OTP kodu direkt return ediliyor — API response'da görünecek
        // Gerçek sistemde: SMS/email gitmeli, kod hiç dönmemeli
        return otpCode;
    }

    public async Task<bool> VerifyOtpAsync(int userId, string otpCode, string purpose)
    {
        // AÇIK: Rate limiting yok — sınırsız deneme
        // AÇIK: Attempt count tracking yok
        // AÇIK: Expiry check yok — OTP süresi dolmaz
        // EXPLOIT: 1000-9999 arası Postman Runner ile dakikalar içinde kırılır
        // CVSS: 7.5 (High) — Missing Rate Limiting
        // Modül 2.2 (OTP Güvenliği) için

        var otp = await _context.OtpRecords
            .Where(o => o.UserId == userId
                     && o.OtpCode == otpCode
                     && o.Purpose == purpose)
            .FirstOrDefaultAsync();

        if (otp == null) return false;

        // AÇIK: OTP kullanıldıktan sonra IsUsed=true yapılmıyor
        // EXPLOIT: Aynı OTP defalarca kullanılabilir (replay attack)
        // Güvenli: otp.IsUsed = true; await _context.SaveChangesAsync();
        return true;
    }
}
