using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class AuthorizationService
{
    private readonly VulnerableDbContext _context;
    private readonly ILogger<AuthorizationService> _logger;

    public AuthorizationService(VulnerableDbContext context, ILogger<AuthorizationService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<AuthorizationResponse> ProcessAsync(AuthorizationRequest request)
    {
        // AÇIK: Fraud detection yok — her işlem onaylanıyor
        // AÇIK: Velocity check yok — aynı kartla dakikada yüzlerce işlem yapılabilir
        // AÇIK: Amount validation yok — negatif tutar kabul ediliyor
        // AÇIK: Blacklist check yok — kısıtlı merchant'larla işlem yapılabilir
        // CVSS: 8.2 (High) — Business Logic Flaw
        // Modül 1.2 (Transaction Lifecycle) ve Modül 2.5 (Fraud Detection) için

        var card = await _context.Cards
            .FirstOrDefaultAsync(c => c.CardNumber == request.CardNumber);

        if (card == null)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "Kart bulunamadı" };

        // AÇIK: CVV doğrulaması sadece string karşılaştırması
        // AÇIK: Expiry date kontrolü yok — süresi dolmuş kart kabul ediliyor
        if (card.CVV != request.CVV)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "CVV hatalı" };

        // AÇIK: Negatif tutara izin veriliyor — bakiye artıyor
        // EXPLOIT: amount: -1000 gönderilirse bakiye 1000 TL artar
        card.AvailableBalance -= request.Amount;

        // AÇIK: Sequential, tahmin edilebilir transaction ID
        // EXPLOIT: TXN000001'den başlayarak tüm işlemler enumerate edilebilir
        var txnCount = await _context.Transactions.CountAsync();
        var transaction = new Transaction
        {
            TransactionId = $"TXN{(txnCount + 1):D6}",
            CardId = card.Id,
            MerchantId = request.MerchantId,
            Amount = request.Amount,
            Currency = request.Currency ?? "TRY",
            Status = "Authorized",
            Description = request.Description ?? string.Empty, // AÇIK: XSS — sanitize edilmiyor
            Notes = request.Notes,                              // AÇIK: XSS vector
            CreatedAt = DateTime.UtcNow,
            // AÇIK: Tahmin edilebilir auth code
            AuthorizationCode = $"AUTH{txnCount + 1}"
        };

        _context.Transactions.Add(transaction);
        await _context.SaveChangesAsync();

        // AÇIK: Full PAN ve CVV response'da dönüyor (PCI DSS ihlali)
        // AÇIK: Bakiye bilgisi gereksiz yere açıklanıyor
        // PCI DSS Requirement 3.4: PAN masked olmalı
        // PCI DSS Requirement 3.2: CVV hiçbir zaman saklanmamalı ve iletilmemeli
        _logger.LogInformation("[AÇIK] Transaction processed: CardNumber={CardNumber}, Amount={Amount}",
            card.CardNumber, request.Amount); // AÇIK: Full PAN log'a yazılıyor

        return new AuthorizationResponse
        {
            IsApproved = true,
            TransactionId = transaction.TransactionId,
            AuthorizationCode = transaction.AuthorizationCode,
            CardNumber = card.CardNumber,       // AÇIK: Full PAN (PCI DSS ihlali)
            CVV = card.CVV,                     // AÇIK: CVV response'da!
            AvailableBalance = card.AvailableBalance,
            RemainingLimit = card.CreditLimit - card.AvailableBalance
        };
    }
}
