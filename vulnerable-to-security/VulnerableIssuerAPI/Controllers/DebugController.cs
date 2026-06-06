using System.Collections;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;
using VulnerableIssuerAPI.Services;

namespace VulnerableIssuerAPI.Controllers;

// AÇIK: Production'da erişilebilir debug endpoint'ler
// AÇIK: Authentication yok — herkes erişebilir
// CVSS: 10.0 (Critical) — Sensitive Data Exposure + RCE seviyesi
// Modül 1.1 (Threat Modeling), Modül 4.2 (Error Handling) ve Modül 4.4 (Architecture) için
[ApiController]
[Route("_debug")]
public class DebugController : ControllerBase
{
    private readonly VulnerableDbContext _context;
    private readonly IConfiguration _configuration;

    public DebugController(VulnerableDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    // GET /_debug/info
    // AÇIK: Environment variables, connection string, OS bilgisi açıkta
    // EXPLOIT: DB connection string'i al, direkt DB'e bağlan
    // EXPLOIT: SECRET_KEY, API_KEY gibi sensitive env var'ları çek
    [HttpGet("info")]
    public IActionResult GetInfo()
    {
        var envVars = new Dictionary<string, string?>();
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            envVars[entry.Key.ToString()!] = entry.Value?.ToString();

        return Ok(new
        {
            //Environment = envVars,                                                  // AÇIK: Tüm env vars
            //ConnectionString = _configuration.GetConnectionString("Default"),       // AÇIK: DB bağlantısı
            //MachineName = Environment.MachineName,
            //OsVersion = Environment.OSVersion.ToString(),
            //DotNetVersion = Environment.Version.ToString(),
            //WorkingDirectory = Directory.GetCurrentDirectory(),
            //ProcessId = Environment.ProcessId
            Status = "Running",
            TimeStamp=DateTime.UtcNow,
            Version = "1.0.0",
        });
    }

    // GET /_debug/users
    // AÇIK: Tüm kullanıcılar ve MD5 şifre hash'leri açıkta
    // EXPLOIT: Hash'leri hashcat / rainbow table ile kır
    // EXPLOIT: https://crackstation.net/ ile password123 → e10adc3949ba59abbe56e057f20f883e
    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users.ToListAsync();
        return Ok(users); // Password hash'leri dahil!
    }

    // GET /_debug/health
    // AÇIK: DB connection string response'da açıkta
    [HttpGet("health")]
    public IActionResult GetHealth()
    {
        //throw new Exception("Kasti bir hata..."); // Modül 4.2 (Error Handling & Information Disclosure) için
        return Ok(new
        {
            Status = "Healthy",
            DatabaseConnected = _context.Database.CanConnect(),
            ConnectionString = _configuration.GetConnectionString("Default"), // AÇIK
            TableCounts = new
            {
                Users = _context.Users.Count(),
                Cards = _context.Cards.Count(),
                Transactions = _context.Transactions.Count(),
                OtpRecords = _context.OtpRecords.Count()
            }
        });
    }

    // POST /_debug/execute-sql
    // AÇIK: Authentication yok, arbitrary SQL çalıştırılabiliyor
    // EXPLOIT: SELECT CardNumber, CVV FROM Cards  (tüm kart verileri)
    // EXPLOIT: INSERT INTO Users ...  (admin kullanıcı ekle)
    // EXPLOIT: DROP TABLE Users  (veritabanı imhası)
    // CVSS: 10.0 (Critical) — Effectively Remote Code Execution
    // Modül 4.2 (Error Handling) ve Modül 4.4 (Architecture) için
    [HttpPost("execute-sql")]
    public async Task<IActionResult> ExecuteSql([FromBody] string sql)
    {
        //GÜVENLİ:Endpoint DEVRE DIŞI!
        return NotFound();
        try
        {
            // AÇIK: Güvenlik kontrolü yok, her SQL çalışıyor
            var result = await _context.Database.ExecuteSqlRawAsync(sql);
            return Ok(new { AffectedRows = result, ExecutedSql = sql }); // AÇIK: SQL echo
        }
        catch (Exception ex)
        {
            // AÇIK: Exception detayları (message, stack trace) client'a gönderiliyor
            // Modül 4.2 (Error Handling & Information Disclosure) için
            return BadRequest(new
            {
                Error = ex.Message,
                StackTrace = ex.StackTrace,
                InnerException = ex.InnerException?.Message
            });
        }
    }

    // GET /_debug/cards
    // AÇIK: Tüm kart verileri (PAN + CVV) auth olmadan açıkta
    // EXPLOIT: Tüm müşterilerin kart bilgilerini çek
    [HttpGet("cards")]
    public async Task<IActionResult> GetAllCards()
    {
        var cards = await _context.Cards.ToListAsync();
        List<Card> maskedCards = new List<Card>();
        cards.ForEach(c =>
        {
            maskedCards.Add(new Card
            {
                Id = c.Id,
                UserId = c.UserId,
                CardNumber = SensitiveDataMasker.MaskPan(c.CardNumber), // Güvenli
                CVV = SensitiveDataMasker.MaskCvv(c.CVV),             // Güvenli
                ExpiryMonth = c.ExpiryMonth,
                ExpiryYear = c.ExpiryYear,
                CardHolderName = c.CardHolderName,
                AvailableBalance = c.AvailableBalance,
                CreditLimit = c.CreditLimit,
                IsActive = c.IsActive,
                CardType = c.CardType,
                BankCode = SensitiveDataMasker.Redacted(c.BankCode)
            });
        });
        return Ok(maskedCards); // Full PAN + CVV — PCI DSS ihlali
    }
}
