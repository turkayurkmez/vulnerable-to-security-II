namespace VulnerableIssuerAPI.Models.DTOs;

public class ResetPasswordRequest
{
    // AÇIK: Token validation yok — herhangi bir string token olarak gönderilirse?
    // AÇIK: Rate limiting yok — brute-force ile token tahmin edilebilir
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}
