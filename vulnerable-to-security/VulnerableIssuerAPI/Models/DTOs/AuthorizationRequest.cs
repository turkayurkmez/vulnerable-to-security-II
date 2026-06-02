namespace VulnerableIssuerAPI.Models.DTOs;

public class AuthorizationRequest
{
    public string CardNumber { get; set; } = string.Empty;
    public string CVV { get; set; } = string.Empty;
    // AÇIK: Amount validation yok — negatif değer kabul ediliyor
    // EXPLOIT: amount: -1000 → bakiye +1000 TL artar
    public decimal Amount { get; set; }
    public string? Currency { get; set; }
    public int MerchantId { get; set; }
    // AÇIK: XSS vector — sanitize edilmiyor, DB'e yazılıyor
    public string? Description { get; set; }
    // AÇIK: XSS vector
    public string? Notes { get; set; }
}
