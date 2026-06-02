namespace VulnerableIssuerAPI.Models.DTOs;

public class CardResponse
{
    public int Id { get; set; }
    // AÇIK: Full PAN dönüyor (PCI DSS ihlali — sadece ilk 6 + son 4 gösterilmeli)
    public string CardNumber { get; set; } = string.Empty;
    // AÇIK: CVV dönüyor (PCI DSS ihlali — CVV hiç gösterilmemeli)
    public string CVV { get; set; } = string.Empty;
    public string ExpiryMonth { get; set; } = string.Empty;
    public string ExpiryYear { get; set; } = string.Empty;
    public string CardHolderName { get; set; } = string.Empty;
    public decimal AvailableBalance { get; set; }
    public decimal CreditLimit { get; set; }
    public bool IsActive { get; set; }
    public string CardType { get; set; } = string.Empty;
}
