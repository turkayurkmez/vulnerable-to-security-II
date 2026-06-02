namespace VulnerableIssuerAPI.Models.DTOs;

public class OtpVerifyRequest
{
    public int UserId { get; set; }
    // AÇIK: Rate limiting yok — sınırsız deneme ile brute-force mümkün
    public string OtpCode { get; set; } = string.Empty;
    public string Purpose { get; set; } = "login";
}
