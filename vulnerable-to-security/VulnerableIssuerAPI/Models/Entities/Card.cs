namespace VulnerableIssuerAPI.Models.Entities;

public class Card
{
    public int Id { get; set; }
    public int UserId { get; set; }
    // AÇIK: PAN plaintext saklanıyor (PCI DSS Requirement 3 ihlali — tokenization zorunlu)
    // EXPLOIT: SQL injection veya IDOR ile tüm PAN'lar çekilebilir
    // CVSS: 9.1 (Critical) — Sensitive Data Exposure
    public string CardNumber { get; set; } = string.Empty;
    // AÇIK: CVV asla saklanmamalı (PCI DSS Requirement 3.2 ihlali)
    // EXPLOIT: DB dump alındığında CVV ile kart kopyalanabilir (card cloning)
    // CVSS: 9.1 (Critical) — PCI DSS Violation
    public string CVV { get; set; } = string.Empty;
    public string ExpiryMonth { get; set; } = string.Empty;
    public string ExpiryYear { get; set; } = string.Empty;
    public string CardHolderName { get; set; } = string.Empty;
    public decimal AvailableBalance { get; set; }
    public decimal CreditLimit { get; set; }
    public bool IsActive { get; set; } = true;
    public string CardType { get; set; } = "CREDIT"; // "CREDIT", "DEBIT"
    public string BankCode { get; set; } = "ISB";

    public User User { get; set; } = null!;
    public ICollection<Transaction> Transactions { get; set; } = new List<Transaction>();
}
