namespace VulnerableIssuerAPI.Models.DTOs;

public class LoginResponse
{
    public string Token { get; set; } = string.Empty;
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    // AÇIK: Gereksiz sensitive bilgi response'da
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
}
