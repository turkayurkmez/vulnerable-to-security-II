using Microsoft.EntityFrameworkCore;
using SQLitePCL;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;
using VulnerableIssuerAPI.StateMachhine;

namespace VulnerableIssuerAPI.Services;

public class AuthorizationService
{
    private readonly VulnerableDbContext _context;
    private readonly ILogger<AuthorizationService> _logger;
    private readonly IdempotencyService _idempotencyService;

    public AuthorizationService(VulnerableDbContext context, ILogger<AuthorizationService> logger, IdempotencyService idempotencyService)
    {
        _context = context;
        _logger = logger;
        _idempotencyService = idempotencyService;
    }

    public async Task<AuthorizationResponse> ProcessAsync(AuthorizationRequest request)
    {

        // CVSS: 8.2 (High) — Business Logic Flaw
        // Modül 1.2 (Transaction Lifecycle) ve Modül 2.5 (Fraud Detection) için

        if (!string.IsNullOrEmpty(request.IdempotencyKey))
        {
            var existing = _idempotencyService.GetExistingRecord(request.IdempotencyKey);
            if (existing != null)
            {
                _logger.LogInformation("Duplicate request detected! {Key} -> {Txn}", request.IdempotencyKey, existing.TransactionId
                );
                return (AuthorizationResponse)existing.CachedResponse;
            }
        }

        var validationError = validateBusinessRules(request);
        if (validationError!=null)
        {
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = validationError };

        }

        var card = await _context.Cards
            .FirstOrDefaultAsync(c => c.CardNumber == request.CardNumber);

        if (card == null)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "Kart bulunamadı" };

        var fraudScore = await Security.FraudDetection.EvaluateFraudRiskAsync(request, card, _context);

        if (fraudScore >= 80)
        {
            _logger.LogWarning("[FRAUD - HIGH] CardId = {CardId}, Score = {Score} - BLOCKED!", card.Id, fraudScore);
            return new AuthorizationResponse
            {
                IsApproved = false,
                ErrorMessage = "İşlem güvenlik nedeniyle reddedildi"
            };
        }
        else if (fraudScore >= 50)
        {
            _logger.LogWarning("[FRAUD - MEDIUM] CardId = {CardId}, Score = {Score} - REVIEW REQUIRED!", card.Id, fraudScore);

            //OTP veya 3D Secure gibi ek doğrulama mekanizması tetiklenebilir. Şimdilik sadece log'a yazıyoruz.

        }





        // AÇIK: CVV doğrulaması sadece string karşılaştırması
        // AÇIK: Expiry date kontrolü yok — süresi dolmuş kart kabul ediliyor
        if (card.CVV != request.CVV)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "CVV hatalı" };

        //Çözüldü: Expiry date kontrolü eklendi, süresi dolmuş kartlar reddediliyor
        var now = DateTime.UtcNow;
        var cardExpiry = new DateTime(card.ExpiryYear, card.ExpiryMonth, 1).AddMonths(1);
        if (now >= cardExpiry)
        {
            _logger.LogWarning("Süresi dolmuş kart: Card={CardId}, Expiry={ExpiryMonth}/{ExpiryYear}", card.Id, card.ExpiryMonth, card.ExpiryYear);

            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "Kartın süresi dolmuş" };

        }

        // AÇIK: Negatif tutara izin veriliyor — bakiye artıyor
        // EXPLOIT: amount: -1000 gönderilirse bakiye 1000 TL artar
        // Çözüldü: Negatif tutar kabul edilmiyor, sadece pozitif tutar onaylanıyor
        if (request.Amount <= 0)
        {
            _logger.LogWarning("Geçersiz tutar: {Amount}, Card={CardId} — Negatif veya sıfır tutar kabul edilmiyor", request.Amount, card.Id);

            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "Tutar pozitif olmalı" };




        }
        //Çözüldü: Maksimum tutar kontrolü eklendi, aşırı büyük işlemler engelleniyor
        const decimal MaxTransactionAmount = 100000m; // AÇIK: Maksimum işlem tutarı kontrolü yok
        if (request.Amount > MaxTransactionAmount)
        {
            _logger.LogWarning("Aşırı tutar: {Amount}, Card={CardId} — Maksimum tutar {MaxAmount}", request.Amount, card.Id, MaxTransactionAmount);

            return new AuthorizationResponse
            {
                IsApproved = false,
                ErrorMessage = $"İşlem tutarı aşıldı!Tutar {MaxTransactionAmount} TL'yi geçemez"
            };
        }

        //f(f(x)) = f(x): Idempotent fonksiyon. Her zaman aynı sonucu verir, tekrar çağrıldığında aynı sonucu döner.
        /*
         * GET: idempotent, safe (state değiştirmez)
         * PUT: idempotent, unsafe (state değiştirebilir)
         * POST: non-idempotent, unsafe (state değiştirebilir)
         * PATCH: non-idempotent, unsafe (state değiştirebilir)
         */

        card.AvailableBalance -= request.Amount;

        // AÇIK: Sequential, tahmin edilebilir transaction ID
        // EXPLOIT: TXN000001'den başlayarak tüm işlemler enumerate edilebilir
        //  var txnCount = await _context.Transactions.CountAsync();
        //  Çözüldü: UUID tabanlı, tahmin edilemez transaction ID kullanılıyor
        var shortId = Guid.NewGuid().ToString("N")[..8].ToUpper(); //UUID tabanlı, tahmin edilemez transaction ID

        var transaction = new Transaction
        {
            TransactionId = $"TXN{shortId}",
            CardId = card.Id,
            MerchantId = request.MerchantId,
            Amount = request.Amount,
            Currency = request.Currency ?? "TRY",
            Status = TransactionStatus.Pending.ToString(),
            Description = request.Description ?? string.Empty, // AÇIK: XSS — sanitize edilmiyor
            Notes = request.Notes,                              // AÇIK: XSS vector
            CreatedAt = DateTime.UtcNow,
            // AÇIK: Tahmin edilebilir auth code
            AuthorizationCode = $"AUTH-{Guid.NewGuid().ToString("N")[..6].ToUpper()}"
        };

        //TransactionStateMachine kullanılarak durum geçişi yapılıyor.
        TransactionStateMachine.Transition(TransactionStatus.Pending, TransactionStatus.Authorized);
        _context.Transactions.Add(transaction);
        await _context.SaveChangesAsync();

        // AÇIK: Full PAN ve CVV response'da dönüyor (PCI DSS ihlali)
        // AÇIK: Bakiye bilgisi gereksiz yere açıklanıyor
        // PCI DSS Requirement 3.4: PAN masked olmalı
        // PCI DSS Requirement 3.2: CVV hiçbir zaman saklanmamalı ve iletilmemeli
        _logger.LogInformation("[AÇIK] Transaction processed: CardNumber={CardNumber}, Amount={Amount}",
            card.CardNumber, request.Amount); // AÇIK: Full PAN log'a yazılıyor

        var pan = card.CardNumber;

        var response = new AuthorizationResponse
        {
            IsApproved = true,
            TransactionId = transaction.TransactionId,
            AuthorizationCode = transaction.AuthorizationCode,
            MaskedCardNumber = $"{pan[..6]}*******{pan[^4..]}",       // PAN masked olarak dönüyor (ilk 6 + son 4 hariç)
            //CVV = card.CVV,                     // CVV kaldırıldı!
            AvailableBalance = card.AvailableBalance,
            RemainingLimit = card.CreditLimit - card.AvailableBalance
        };

        if (!string.IsNullOrWhiteSpace(request.IdempotencyKey))
        {
            _idempotencyService.StoreRecord(request.IdempotencyKey, transaction.TransactionId, response);
        }

        return response;
    }


    private string? validateBusinessRules(AuthorizationRequest request)
    {
        var supportedCurrencies = new[] { "TRY", "USD", "EUR" };
        var currency = request.Currency.ToUpper() ?? "TRY";
        if (!supportedCurrencies.Contains(currency))
        {
            return $"Desteklenmeyen para birimi: {currency}";
        }


        return null;
    }
}
