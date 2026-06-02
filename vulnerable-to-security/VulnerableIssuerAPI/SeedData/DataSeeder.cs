using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.SeedData;

public static class DataSeeder
{
    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<VulnerableDbContext>();

        await context.Database.EnsureCreatedAsync();

        // Idempotent — daha önce seed edilmişse tekrar ekleme
        if (await context.Users.AnyAsync()) return;

        // ============================================================
        // KULLANICILAR — MD5 hash'li şifreler
        // AÇIK: MD5 kullanılıyor (PCI DSS ihlali)
        // ============================================================
        var users = new List<User>
        {
            new User
            {
                Username = "ahmet.yilmaz",
                // AÇIK: password123 → MD5 → 482c811da5d5b4bc6d497ffa98491e38
                Password = ComputeMd5("password123"),
                Email = "ahmet@example.com",
                FullName = "Ahmet Yılmaz",
                Role = "customer",
                IsActive = true,
                CreatedAt = DateTime.UtcNow.AddDays(-30),
                SecurityAnswer = "istanbul" // AÇIK: Plaintext güvenlik sorusu cevabı
            },
            new User
            {
                Username = "fatma.kaya",
                // AÇIK: secure456 → MD5 → 7b1a1b25d3f30e4da5d09aa5b20bd7c4
                Password = ComputeMd5("secure456"),
                Email = "fatma@example.com",
                FullName = "Fatma Kaya",
                Role = "customer",
                IsActive = true,
                CreatedAt = DateTime.UtcNow.AddDays(-15),
                SecurityAnswer = "ankara" // AÇIK: Plaintext
            },
            new User
            {
                Username = "mehmet.demir",
                // AÇIK: admin789 → MD5 → 45e6b9f13f0d20a820aec67398d41571
                Password = ComputeMd5("admin789"),
                Email = "mehmet@example.com",
                FullName = "Mehmet Demir",
                Role = "admin",
                IsActive = true,
                CreatedAt = DateTime.UtcNow.AddDays(-60),
                SecurityAnswer = "izmir" // AÇIK: Plaintext
            },
            new User
            {
                Username = "test.merchant",
                // AÇIK: merchant123 → MD5
                Password = ComputeMd5("merchant123"),
                Email = "merchant@example.com",
                FullName = "Test Merchant",
                Role = "merchant",
                IsActive = true,
                CreatedAt = DateTime.UtcNow.AddDays(-7)
            }
        };

        context.Users.AddRange(users);
        await context.SaveChangesAsync();

        // ============================================================
        // KARTLAR — PAN ve CVV plaintext
        // AÇIK: PCI DSS Requirement 3 ihlali
        // ============================================================
        var cards = new List<Card>
        {
            new Card
            {
                UserId = users[0].Id, // ahmet.yilmaz
                // AÇIK: Full PAN plaintext (Visa, Luhn geçerli)
                CardNumber = "4532123456789010",
                // AÇIK: CVV plaintext (PCI DSS Requirement 3.2 ihlali)
                CVV = "123",
                ExpiryMonth = "12",
                ExpiryYear = "2026",
                CardHolderName = "AHMET YILMAZ",
                AvailableBalance = 15000.00m,
                CreditLimit = 20000.00m,
                IsActive = true,
                CardType = "CREDIT",
                BankCode = "ISB"
            },
            new Card
            {
                UserId = users[0].Id, // ahmet.yilmaz (ikinci kart)
                // AÇIK: Full PAN plaintext (Mastercard, Luhn geçerli)
                CardNumber = "5425233430109903",
                CVV = "456",
                ExpiryMonth = "06",
                ExpiryYear = "2025",
                CardHolderName = "AHMET YILMAZ",
                AvailableBalance = 8500.00m,
                CreditLimit = 10000.00m,
                IsActive = true,
                CardType = "CREDIT",
                BankCode = "ISB"
            },
            new Card
            {
                UserId = users[1].Id, // fatma.kaya
                // AÇIK: Full PAN plaintext (Visa, Luhn geçerli)
                CardNumber = "4716158604553580",
                CVV = "789",
                ExpiryMonth = "03",
                ExpiryYear = "2027",
                CardHolderName = "FATMA KAYA",
                AvailableBalance = 22000.00m,
                CreditLimit = 25000.00m,
                IsActive = true,
                CardType = "CREDIT",
                BankCode = "ISB"
            }
        };

        context.Cards.AddRange(cards);
        await context.SaveChangesAsync();

        // ============================================================
        // İŞLEMLER
        // AÇIK: Sequential TransactionId (TXN000001, TXN000002...)
        // ============================================================
        var transactions = new List<Transaction>
        {
            new Transaction
            {
                TransactionId = "TXN000001",
                CardId = cards[0].Id,
                MerchantId = 1001,
                Amount = 250.00m,
                Currency = "TRY",
                Status = "Authorized",
                Description = "Trendyol - Elektronik",
                CreatedAt = DateTime.UtcNow.AddDays(-5),
                AuthorizationCode = "AUTH1"
            },
            new Transaction
            {
                TransactionId = "TXN000002",
                CardId = cards[0].Id,
                MerchantId = 1002,
                Amount = 89.90m,
                Currency = "TRY",
                Status = "Settled",
                Description = "Migros Market",
                CreatedAt = DateTime.UtcNow.AddDays(-3),
                AuthorizationCode = "AUTH2"
            },
            new Transaction
            {
                TransactionId = "TXN000003",
                CardId = cards[1].Id,
                MerchantId = 1003,
                Amount = 4500.00m,
                Currency = "TRY",
                Status = "Captured",
                Description = "Apple Store",
                CreatedAt = DateTime.UtcNow.AddDays(-1),
                AuthorizationCode = "AUTH3"
            },
            new Transaction
            {
                TransactionId = "TXN000004",
                CardId = cards[2].Id, // fatma.kaya'nın kartı
                MerchantId = 1004,
                Amount = 150.00m,
                Currency = "TRY",
                Status = "Failed",
                Description = "Booking.com",
                CreatedAt = DateTime.UtcNow.AddHours(-2),
                // AÇIK: İç hata detayı client'a gösteriliyor
                FailureReason = "Yetersiz bakiye - DB hata kodu: ERR_INSUF_FUNDS_042"
            },
            new Transaction
            {
                // AÇIK: Şüpheli işlem — BIN test, mikro ödeme (fraud pattern)
                TransactionId = "TXN000005",
                CardId = cards[0].Id,
                MerchantId = 9999, // AÇIK: Var olmayan/şüpheli merchant
                Amount = 0.01m,
                Currency = "TRY",
                Status = "Authorized",
                Description = "BIN test küçük işlem", // Fraud pattern göstergesi
                Notes = "<script>alert('XSS')</script>", // AÇIK: Stored XSS
                CreatedAt = DateTime.UtcNow.AddMinutes(-30),
                AuthorizationCode = "AUTH5"
            }
        };

        context.Transactions.AddRange(transactions);
        await context.SaveChangesAsync();

        // ============================================================
        // OTP KAYITLARI — exploit için hazır
        // AÇIK: Süresi geçmiş OTP'ler hâlâ geçerli (expiry yok)
        // AÇIK: IsUsed flag yok (replay attack)
        // ============================================================
        var otpRecords = new List<OtpRecord>
        {
            new OtpRecord
            {
                UserId = users[0].Id, // ahmet.yilmaz
                OtpCode = "1234",
                Purpose = "login",
                // AÇIK: 3 gün önce oluşturulmuş ama sistem hâlâ kabul ediyor
                CreatedAt = DateTime.UtcNow.AddDays(-3)
            },
            new OtpRecord
            {
                UserId = users[1].Id, // fatma.kaya
                OtpCode = "5678",
                Purpose = "transaction",
                CreatedAt = DateTime.UtcNow
            }
        };

        context.OtpRecords.AddRange(otpRecords);
        await context.SaveChangesAsync();

        // ============================================================
        // PASSWORD RESET TOKEN — öngörülebilir format
        // AÇIK: {userId}_{DateTime.Ticks} formatı tahmin edilebilir
        // ============================================================
        var resetTokens = new List<PasswordResetToken>
        {
            new PasswordResetToken
            {
                UserId = users[0].Id, // ahmet.yilmaz
                // AÇIK: Tahmin edilebilir token formatı
                Token = "1_638500000000000",
                // AÇIK: Dün oluşturulmuş ama hâlâ geçerli (expiry yok)
                CreatedAt = DateTime.UtcNow.AddDays(-1)
            }
        };

        context.PasswordResetTokens.AddRange(resetTokens);
        await context.SaveChangesAsync();

        Console.WriteLine("[DataSeeder] Seed data başarıyla yüklendi.");
        Console.WriteLine("[DataSeeder] Test kullanıcıları:");
        Console.WriteLine("  ahmet.yilmaz / password123 (customer)");
        Console.WriteLine("  fatma.kaya   / secure456   (customer)");
        Console.WriteLine("  mehmet.demir / admin789    (admin)");
        Console.WriteLine("  test.merchant/ merchant123 (merchant)");
    }

    private static string ComputeMd5(string input)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLower();
    }
}
