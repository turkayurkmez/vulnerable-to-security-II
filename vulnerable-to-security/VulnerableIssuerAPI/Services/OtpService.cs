using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Cryptography;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class OtpService
{
    private readonly VulnerableDbContext _context;
    private readonly IMemoryCache _cache;

    public OtpService(VulnerableDbContext context, IMemoryCache cache)
    {
        _context = context;
        _cache = cache;
    }

    public async Task<string> GenerateOtpAsync(int userId, string purpose, int digits=6)
    {
        // AÇIK: System.Random — cryptographically secure değil
        // Güvenli alternatif: RandomNumberGenerator.GetInt32(100000, 999999)
        // AÇIK: 4 haneli = 10.000 kombinasyon — brute-force trivial
        // Güvenli alternatif: 6+ haneli TOTP (RFC 6238)
        // CVSS: 8.6 (High) — Insufficient Entropy
        // Modül 2.2 (OTP Güvenliği) için

        string otpCode = generateSecureOtp(digits:6); // Zero-pad to desired length
        // Güvenli: 6 haneli OTP için 1.000.000 kombinasyon — brute-force çok zorlaşır
        // Rejection sampling riski daha da düşürecek bir algoritma da kullanılabilir.


        //var random = new Random();
        //var otpCode = random.Next(1000, 9999).ToString();

        // AÇIK: Önceki OTP'ler silinmiyor — tüm geçmiş OTP'ler hâlâ geçerli
        // AÇIK: Rate limiting kontrolü yapılmıyor (bu servis katmanında da olmaz)
        var otpRecord = new OtpRecord
        {
            UserId = userId,
            OtpCode = otpCode,
            Purpose = purpose,
            CreatedAt = DateTime.UtcNow,

            // AÇIK: ExpiresAt set edilmiyor — OTP sonsuza kadar geçerli
            // AÇIK: IsUsed flag yok — replay attack mümkün
            ExpiryDate = DateTime.UtcNow.AddMinutes(5), // Güvenli: OTP 5 dakika geçerli olsun
            IsUsed = false // Güvenli: OTP kullanıldıktan sonra geçersiz hale getirilsin
        };

        var cacheKey = $"otp:{userId}_{purpose}";

        var cacheOptions = new MemoryCacheEntryOptions()
                               .SetAbsoluteExpiration(TimeSpan.FromSeconds(90))
                               .SetPriority(CacheItemPriority.High);

        _cache.Set(cacheKey, otpRecord, cacheOptions);

        _context.OtpRecords.Add(otpRecord);
        await _context.SaveChangesAsync();

        // AÇIK: OTP kodu log'a yazılıyor (log injection riski + sensitive data exposure)
        // EXPLOIT: Log dosyasına erişen kişi tüm OTP'leri görebilir
        Console.WriteLine($"[DEBUG] OTP generated for userId={userId}: {otpCode}");

        // AÇIK: OTP kodu direkt return ediliyor — API response'da görünecek
        // Gerçek sistemde: SMS/email gitmeli, kod hiç dönmemeli
        return otpCode;
    }

    private static string generateSecureOtp(int digits)
    {
        var bytes = new byte[4];
        RandomNumberGenerator.Fill(bytes);

        var value = BitConverter.ToUInt32(bytes, 0);
        var max = (uint)Math.Pow(10, digits);
        var otpCode = (value % max).ToString($"D{digits}");
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

        var cacheKey = $"otp:{userId}_{purpose}";

        if (!_cache.TryGetValue(cacheKey, out OtpRecord? otpRecord) || otpRecord == null)
        {
            return await Task.FromResult(false); // Cache'de yoksa veritabanına bile bakmaya gerek yok
        }

        if (otpRecord.IsUsed)
        {
            return await Task.FromResult( false);
        }

        //Timing attack'lere karşı güvenli karşılaştırma. Timing Attack: Bir saldırgan, iki değerin ne kadar süreyle eşleştiğini ölçerek hangi karakterlerin doğru olduğunu tahmin edebilir. Sabit zamanlı karşılaştırma, bu tür saldırılara karşı koruma sağlar.
        var isValid = CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(otpRecord.OtpCode),
            System.Text.Encoding.UTF8.GetBytes(otpCode));

        if (!isValid)
        {
            return await Task.FromResult(false);
        }

        otpRecord.IsUsed = true; // OTP kullanıldıktan sonra geçersiz hale getir

        var shortExpiry = new MemoryCacheEntryOptions()
                             .SetAbsoluteExpiration(TimeSpan.FromSeconds(5));
        
        _cache.Set(cacheKey, otpRecord, shortExpiry); // Cache'deki kaydı güncelle
        //shortExpiry ile cache'deki OTP kaydının 5 saniye sonra geçersiz hale gelmesini sağlıyoruz. Bu,race condition'lara karşı ek bir koruma sağlar ve replay attack riskini azaltır.

        //var otp = await _context.OtpRecords
        //    .Where(o => o.UserId == userId
        //             && o.OtpCode == otpCode
        //             && o.Purpose == purpose)
        //    .FirstOrDefaultAsync();

       // if (otp == null) return false;



        // AÇIK: OTP kullanıldıktan sonra IsUsed=true yapılmıyor
        // EXPLOIT: Aynı OTP defalarca kullanılabilir (replay attack)
        // Güvenli: otp.IsUsed = true; await _context.SaveChangesAsync();
        return await Task.FromResult( true);
    }
}
