namespace VulnerableIssuerAPI.Models.DTOs;

public class AuthorizationResponse
{
    public bool IsApproved { get; set; }
    public string? TransactionId { get; set; }
    public string? AuthorizationCode { get; set; }
    // AÇIK: Full PAN response'da dönüyor (PCI DSS ihlali)
    // PCI DSS Requirement 3: PAN masked olmalı (ilk 6 + son 4 hariç)
    public string? MaskedCardNumber { get; set; }
    // AÇIK: CVV response'da dönüyor (PCI DSS Requirement 3.2 ihlali)
    // CVV post-authorization asla saklanmamalı ve iletilmemeli
 //   public string? CVV { get; set; }
    // AÇIK: Bakiye bilgisi gereksiz yere açıklanıyor
    public decimal AvailableBalance { get; set; }
    public decimal RemainingLimit { get; set; }
    public string? ErrorMessage { get; set; }
}
