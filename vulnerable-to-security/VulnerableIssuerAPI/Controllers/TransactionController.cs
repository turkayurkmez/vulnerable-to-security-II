using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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

    public TransactionController(VulnerableDbContext context, AuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }

    // POST /api/transactions/authorize
    // AÇIK: Authentication yok — herkes yetkilendirme yapabilir
    // AÇIK: Input validation yok — negatif tutar, XSS, geçersiz kart vs hepsi kabul
    // AÇIK: Idempotency yok — aynı istek iki kez gönderilirse çifte işlem oluşur
    // Modül 1.2 (Transaction Lifecycle), Modül 3.1 (Input Validation), Modül 3.2 (Idempotency)
    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize([FromBody] AuthorizationRequest request)
    {
        var response = await _authorizationService.ProcessAsync(request);
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
            .Include(t => t.Card)
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

        // AÇIK: FromSqlRaw ile parametre binding yapılmadan string concatenation
        // Güvenli alternatif: .FromSqlRaw("SELECT * FROM Transactions WHERE Description LIKE {0}", $"%{query}%")
        var sql = $"SELECT * FROM Transactions WHERE Description LIKE '%{query}%' OR Notes LIKE '%{query}%'";

        var transactions = await _context.Transactions
            .FromSqlRaw(sql)
            .ToListAsync();

        // AÇIK: Hata mesajları SQL detaylarını içerebilir (global exception handler sayesinde)
        // AÇIK: Input reflection — query string XSS vector olarak response'da dönüyor
        return Ok(new
        {
            Query = query,  // AÇIK: Sanitize edilmemiş input reflection
            Count = transactions.Count,
            Results = transactions
        });
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
