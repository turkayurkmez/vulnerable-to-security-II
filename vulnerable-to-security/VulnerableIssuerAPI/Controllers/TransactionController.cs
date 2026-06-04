using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Services;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/transactions")]
public class TransactionController : ControllerBase
{
    private readonly VulnerableDbContext _context;
    private readonly AuthorizationService _authorizationService;
    private readonly ILogger<TransactionController> _log;

    public TransactionController(VulnerableDbContext context, AuthorizationService authorizationService, ILogger<TransactionController> logger)
    {
        _context = context;
        _authorizationService = authorizationService;
        _log = logger;
    }


    private readonly TimeSpan ReplayWindow = TimeSpan.FromMinutes(5);
    // POST /api/transactions/authorize
    // AÇIK: Authentication yok — herkes yetkilendirme yapabilir
    // AÇIK: Input validation yok — negatif tutar, XSS, geçersiz kart vs hepsi kabul
    // AÇIK: Idempotency yok — aynı istek iki kez gönderilirse çifte işlem oluşur
    // Modül 1.2 (Transaction Lifecycle), Modül 3.1 (Input Validation), Modül 3.2 (Idempotency)
    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize([FromBody] AuthorizationRequest request, [FromHeader(Name = "X-Request-Timestamp")] string? timestampHeader)
    {
        if (!string.IsNullOrEmpty(timestampHeader))
        {
            if (DateTimeOffset.TryParse(timestampHeader, out var requestTime) || DateTimeOffset.UtcNow - requestTime > ReplayWindow)
            {
                return BadRequest(new { error = "İstek süresi dolmuş." });
            }
        }
        var response = await _authorizationService.ProcessAsync(request);
        if (!response.IsApproved)
        {
            return BadRequest(new { error = "İşlem reddedildi" });
        }
        _log.LogInformation("Authorized. UserId={user}, Transaction:{txn}", User.FindFirstValue("userId"), response.TransactionId);
        return Ok(response);
    }

    // GET /api/transactions
    // AÇIK: Authentication yok — herkes tüm işlemleri görebilir
    // AÇIK: Pagination yok — tüm DB dökülüyor (DoS riski, memory exhaustion)
    // AÇIK: Ownership check yok — farklı kullanıcıların işlemleri görünür
    // Modül 3.4 (Rate Limiting & DoS Protection) için
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        // AÇIK: Tüm işlemler + Card entity dahil — PAN açıkta
        var transactions = await _context.Transactions
            //   .Include(t => t.Card)
            .ToListAsync();
        return Ok(transactions); // Card entity dahil — PAN açıkta (PCI DSS ihlali)
    }

    // GET /api/transactions/search?query=...
    // AÇIK: SQL Injection — string concatenation ile sorgu oluşturuluyor
    // EXPLOIT: ?query=' OR '1'='1   (tüm kayıtlar döner)
    // EXPLOIT: ?query=' UNION SELECT CardNumber,CVV,ExpiryMonth,ExpiryYear,CardHolderName,6,7,8,9,10 FROM Cards; --
    // EXPLOIT: ?query='; DROP TABLE Transactions; --
    // PCI DSS: Requirement 6.3.1 — injection flaw prevention zorunlu
    // CVSS: 10.0 (Critical) — SQL Injection
    // Modül 3.1 (Input Validation & Output Encoding) için
    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string query)
    {
        if (string.IsNullOrEmpty(query))
            return BadRequest("Query parametresi gerekli");


        // Güvenli alternatif: .FromSqlRaw("SELECT * FROM Transactions WHERE Description LIKE {0}", $"%{query}%")
        //' GO drop database xxx GO --
        var searchTerm = $"%{query}%";
        //var sql = $"SELECT * FROM Transactions WHERE Description LIKE '%{query}%' OR Notes LIKE '%{query}%'";

        var transactions = await _context.Transactions
            .FromSqlRaw("SELECT * FROM Transactions WHERE Description LIKE {0} OR Notes LIKE {0}", searchTerm)
            .ToListAsync();

        // AÇIK: Hata mesajları SQL detaylarını içerebilir (global exception handler sayesinde)
        // AÇIK: Input reflection — query string XSS vector olarak response'da dönüyor
        return Ok(new
        {
            // Query = query,  // AÇIK: Sanitize edilmemiş input reflection

            Count = transactions.Count,
            Results = transactions.Select(t => new
            {
                t.TransactionId,
                t.MerchantId,
                t.Amount,
                t.Currency,
                t.Status,
                Description = HtmlEncode(t.Description),
                Notes = HtmlEncode(t.Notes)

            })
        });
    }

    private string HtmlEncode(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        return input.Replace("&", "&amp;")
                    .Replace("<", "&lt;")
                    .Replace(">", "&gt;")
                    .Replace("\"", "&quot;")
                    .Replace("'", "&#39;");

    }

    // GET /api/transactions/{id}
    // AÇIK: IDOR — başka kullanıcının işlemi görülebilir
    // EXPLOIT: TXN000001, TXN000002... enumerate edilerek tüm işlemler görülür
    // Modül 1.3 (STRIDE: Information Disclosure) için
    [HttpGet("{id}")]
    [Authorize]
    public async Task<IActionResult> GetTransaction(string id)
    {
        // AÇIK: Ownership check yok — herkes herkesin işlemini görebilir
        var transaction = await _context.Transactions
            .Include(t => t.Card)
            .FirstOrDefaultAsync(t => t.TransactionId == id);

        if (transaction == null)
            return NotFound(new { error = $"İşlem bulunamadı: {id}" }); // AÇIK: ID reflection

        return Ok(transaction); // Card entity dahil — PAN açıkta
    }
}
