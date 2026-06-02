namespace VulnerableIssuerAPI.Models.DTOs;

public class OtpSendRequest
{
    // AÇIK: userId doğrulama yok — herkes başkası adına OTP isteyebilir
    public int UserId { get; set; }
    public string Purpose { get; set; } = "login";
}
