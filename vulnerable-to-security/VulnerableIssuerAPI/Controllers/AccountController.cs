using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/account")]
[Authorize]
public class AccountController : ControllerBase
{
    private readonly VulnerableDbContext _context;

    public AccountController(VulnerableDbContext context)
    {
        _context = context;
    }

    // GET /api/account/profile/{userId}
    // AÇIK: IDOR — başka kullanıcının profilini görme
    // EXPLOIT: /api/account/profile/2 ile fatma.kaya'nın profili görülür
    // CVSS: 6.5 (Medium) — IDOR
    [HttpGet("profile/{userId}")]
    public async Task<IActionResult> GetProfile(int userId)
    {
        // AÇIK: JWT'deki userId ile parametre karşılaştırılmıyor
        var user = await _context.Users
            .Include(u => u.Cards)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
            return NotFound(new { error = "Kullanıcı bulunamadı" });

        // AÇIK: SecurityAnswer plaintext dönüyor
        // AÇIK: Kart bilgileri (full PAN + CVV) dahil ediliyor
        return Ok(new
        {
            user.Id,
            user.Username,
            user.Email,
            user.FullName,
            user.Role,
            user.SecurityAnswer,  // AÇIK: Güvenlik sorusu cevabı açıkta
            Cards = user.Cards.Select(c => new
            {
                c.Id,
                c.CardNumber,  // AÇIK: Full PAN
                c.CVV,         // AÇIK: CVV
                c.ExpiryMonth,
                c.ExpiryYear,
                c.AvailableBalance
            })
        });
    }

    // GET /api/account/cards/{userId}
    // AÇIK: IDOR — başka kullanıcının kartlarını görme
    [HttpGet("cards/{userId}")]
    public async Task<IActionResult> GetUserCards(int userId)
    {
        // AÇIK: Ownership check yok
        var cards = await _context.Cards
            .Where(c => c.UserId == userId)
            .ToListAsync();

        return Ok(cards); // Full PAN + CVV dahil
    }
}
