using System.ComponentModel.DataAnnotations;

namespace VulnerableIssuerAPI.Models.DTOs;

public class AuthorizationRequest
{
    [Required]
    [RegularExpression(@"^\d{16,19}$", ErrorMessage = "Card number must be 16 digits.")]
    public string CardNumber { get; set; } = string.Empty;
    [Required]
    [RegularExpression(@"^\d{3,4}$", ErrorMessage ="Geçersiz CVV")]
    public string CVV { get; set; } = string.Empty;
    // AÇIK: Amount validation yok — negatif değer kabul ediliyor
    // EXPLOIT: amount: -1000 → bakiye +1000 TL artar

    [Range(1,1_000_000, ErrorMessage = "Amount must be between 1 and 1,000,000.")]
    public decimal Amount { get; set; }
    public string? Currency { get; set; }
    public int MerchantId { get; set; }
    // AÇIK: XSS vector — sanitize edilmiyor, DB'e yazılıyor
    public string? Description { get; set; }
    // AÇIK: XSS vector
    public string? Notes { get; set; }

    //Güvenli: İstemci her benzersiz işlem için benzersiz bir idempotency key göndermeli, sunucu bu key'i kaydedip aynı key ile gelen tekrar eden istekleri reddedebilir veya önceki sonucu dönebilir.
    public string? IdempotencyKey { get; set; } 
}
