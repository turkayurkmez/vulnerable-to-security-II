using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/cards")]
[Authorize] // JWT var ama validasyon zayıf (alg:none bypass mümkün)
public class CardController : ControllerBase
{
    private readonly VulnerableDbContext _context;

    public CardController(VulnerableDbContext context)
    {
        _context = context;
    }

    // GET /api/cards
    // AÇIK: Tüm kartlar dönüyor, ownership check yok
    // EXPLOIT: Herhangi bir geçerli JWT (hatta alg:none) ile tüm kartlar listelenir
    // CVSS: 8.1 (High) — Broken Object Level Authorization (OWASP API1)
    // Modül 1.3 (STRIDE) ve Modül 4.3 (OWASP Top 10) için
    [HttpGet]
    public async Task<IActionResult> GetAllCards()
    {
        // AÇIK: JWT'deki userId ile filtreleme yapılmıyor — TÜM kartlar dönüyor
        // AÇIK: CVV ve full PAN response'da (PCI DSS Requirement 3 ihlali)
        var cards = await _context.Cards.ToListAsync();
        return Ok(cards); // PCI DSS ihlali: PAN + CVV açıkta
    }

    // GET /api/cards/{id}
    // AÇIK: IDOR — başka kullanıcının kartına erişim
    // EXPLOIT: id=1,2,3... ile farklı kullanıcıların kartları görülür
    // CVSS: 8.1 (High) — IDOR (OWASP API3:2023)
    // Modül 1.3 (STRIDE: Information Disclosure) için
    [HttpGet("{id}")]
    public async Task<IActionResult> GetCard(int id)
    {
        var card = await _context.Cards.FindAsync(id);

        if (card == null) return NotFound(new { error = "Kart bulunamadı" });

        // AÇIK: Ownership check yok — token'daki userId ile card.UserId karşılaştırılmıyor
        // Güvenli: var userId = int.Parse(User.FindFirst("userId")!.Value);
        //          if (card.UserId != userId) return Forbid();
        // AÇIK: Full PAN ve CVV dönüyor
        return Ok(new
        {
            card.Id,
            card.CardNumber,        // AÇIK: Full PAN (PCI DSS ihlali)
            card.CVV,               // AÇIK: CVV (PCI DSS ihlali)
            card.ExpiryMonth,
            card.ExpiryYear,
            card.CardHolderName,
            card.AvailableBalance,
            card.CreditLimit,
            card.IsActive
        });
    }

    // GET /api/cards/{id}/balance
    // AÇIK: IDOR + unnecessary balance disclosure
    // EXPLOIT: Başka kullanıcının bakiyesini görme
    [HttpGet("{id}/balance")]
    public async Task<IActionResult> GetBalance(int id)
    {
        var card = await _context.Cards.FindAsync(id);
        if (card == null) return NotFound();

        // AÇIK: Ownership check yok
        return Ok(new
        {
            CardId = card.Id,
            CardNumber = card.CardNumber, // AÇIK: Full PAN gereksiz yere dönüyor
            AvailableBalance = card.AvailableBalance,
            CreditLimit = card.CreditLimit,
            UsedLimit = card.CreditLimit - card.AvailableBalance
        });
    }
}
