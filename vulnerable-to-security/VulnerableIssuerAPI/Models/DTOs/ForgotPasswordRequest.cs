namespace VulnerableIssuerAPI.Models.DTOs;

public class ForgotPasswordRequest
{
    // AÇIK: Bu email var mı yok mu bilgisi response'da sızdırılıyor (account enumeration)
    public string Email { get; set; } = string.Empty;
}
