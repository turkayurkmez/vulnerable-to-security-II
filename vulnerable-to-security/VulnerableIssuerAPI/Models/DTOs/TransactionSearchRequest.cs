namespace VulnerableIssuerAPI.Models.DTOs;

public class TransactionSearchRequest
{
    // AÇIK: Bu query string concatenation ile SQL'e ekleniyor
    // EXPLOIT: ' OR '1'='1  veya UNION SELECT ile kart bilgileri çekilebilir
    public string Query { get; set; } = string.Empty;
}
