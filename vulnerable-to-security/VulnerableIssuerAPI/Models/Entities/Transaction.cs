namespace VulnerableIssuerAPI.Models.Entities;

public class Transaction
{
    public int Id { get; set; }
    // AÇIK: Sequential ID — saldırgan tüm işlem ID'lerini tahmin edebilir
    // EXPLOIT: TXN000001, TXN000002... şeklinde enumerate edilebilir
    // CVSS: 5.3 (Medium) — Predictable Resource Location
    public string TransactionId { get; set; } = string.Empty;
    public int CardId { get; set; }
    // AÇIK: MerchantId validation yok — herhangi bir merchant ID kabul ediliyor
    // EXPLOIT: Var olmayan bir merchant ile işlem yapılabilir
    public int MerchantId { get; set; }
    // AÇIK: Negative amount kabul ediliyor (business logic flaw)
    // EXPLOIT: -500 TL işlem = bakiye artışı (para transferi tersine çevrilebilir)
    // CVSS: 8.2 (High) — Business Logic Flaw
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "TRY";
    // AÇIK: Enum yerine string — "Authorized", "authorized", "AUTHORIZED" hepsi geçerli
    // EXPLOIT: Status manipulation ile işlem durumu değiştirilebilir
    public string Status { get; set; } = "Pending";
    // AÇIK: XSS vector — HTML/JS inject edilebilir
    // EXPLOIT: <script>alert('XSS')</script> description'a yazılabilir
    // CVSS: 6.1 (Medium) — Stored XSS
    public string Description { get; set; } = string.Empty;
    // AÇIK: XSS vector
    public string? Notes { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? AuthorizationCode { get; set; }
    // AÇIK: İç hata detayları client'a gösteriliyor (information disclosure)
    public string? FailureReason { get; set; }

    public Card Card { get; set; } = null!;
}
