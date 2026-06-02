using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class PasswordResetService
{
    private readonly VulnerableDbContext _context;

    public PasswordResetService(VulnerableDbContext context)
    {
        _context = context;
    }

    public async Task<string> GenerateResetTokenAsync(string email)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        // AÇIK: Account enumeration — kullanıcının var olup olmadığı sızdırılıyor
        // EXPLOIT: Farklı email'ler deneyerek hangi hesapların var olduğu öğrenilir
        // Güvenli alternatif: Her durumda aynı mesaj ("Eğer email kayıtlıysa link gönderildi")
        // CVSS: 5.3 (Medium) — Information Disclosure
        // Modül 2.1 (Password Reset Güvenliği) için
        if (user == null)
            return "Hata: Bu email adresi kayıtlı değil"; // Saldırgana bilgi sızdırıyor!

        // AÇIK: Tahmin edilebilir token = userId + DateTime.Ticks
        // EXPLOIT: userId=1 ise ve yaklaşık zaman biliniyorsa token tahmin edilebilir
        // Güvenli alternatif: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        // CVSS: 7.5 (High) — Weak Token Generation
        var token = $"{user.Id}_{DateTime.Now.Ticks}";

        var resetToken = new PasswordResetToken
        {
            UserId = user.Id,
            Token = token,
            CreatedAt = DateTime.Now
            // AÇIK: ExpiresAt yok — token sonsuza kadar geçerli
            // Güvenli: ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        };

        _context.PasswordResetTokens.Add(resetToken);
        await _context.SaveChangesAsync();

        // AÇIK: Token direkt response'da dönüyor (email gönderilmiyor)
        // AÇIK: Rate limiting yok — dakikada yüzlerce token üretilebilir
        return token;
    }

    public async Task<bool> ResetPasswordAsync(string token, string newPassword)
    {
        // AÇIK: Rate limiting yok — token brute-force mümkün
        var resetToken = await _context.PasswordResetTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.Token == token);

        if (resetToken == null) return false;

        // AÇIK: Expiry kontrolü yok — 6 ay önce üretilen token hâlâ geçerli
        // Güvenli: if (resetToken.ExpiresAt < DateTime.UtcNow) return false;

        // AÇIK: MD5 hash — çoktan kırılmış, rainbow table saldırısına açık
        // PCI DSS: Requirement 8.2.1 — strong cryptography zorunlu
        // Güvenli: BCrypt.HashPassword(newPassword, workFactor: 12)
        // CVSS: 6.5 (Medium) — Weak Password Hashing
        resetToken.User.Password = ComputeMd5(newPassword);
        await _context.SaveChangesAsync();

        // AÇIK: Token kullanıldıktan sonra silinmiyor
        // EXPLOIT: Aynı token ile tekrar şifre değiştirilebilir (replay attack)
        // Güvenli: _context.PasswordResetTokens.Remove(resetToken);
        return true;
    }

    private static string ComputeMd5(string input)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLower();
    }
}
