using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;
using VulnerableIssuerAPI.Services;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    // AÇIK: Weak JWT secret — hardcoded, sadece 6 karakter
    // EXPLOIT: hashcat ile saniyeler içinde kırılabilir
    // CVSS: 9.1 (Critical) — Broken Authentication
    // Modül 2.4 (JWT Implementasyonu) için
    private const string JwtSecret = "secret-for-demo-and-this-data-must-be-128-bit"; // AÇIK: Çok zayıf bir secret

    private readonly VulnerableDbContext _context;
    private readonly OtpService _otpService;
    private readonly PasswordResetService _passwordResetService;

    public AuthController(VulnerableDbContext context, OtpService otpService, PasswordResetService passwordResetService)
    {
        _context = context;
        _otpService = otpService;
        _passwordResetService = passwordResetService;
    }

    // POST /api/auth/login
    // AÇIK: Brute-force koruması yok — rate limiting yok
    // AÇIK: Account lockout yok — sınırsız deneme
    // EXPLOIT: Şifreleri tek tek deneyebilirsin, hesap kilitlenmez
    // Modül 2.4 (JWT) ve Modül 3.4 (Rate Limiting) için
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // AÇIK: Timing attack — kullanıcı bulunamazsa vs şifre yanlışsa farklı response süresi
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null)
            return Unauthorized(new { error = "Kullanıcı bulunamadı" }); // AÇIK: Enumeration!

        var passwordHash = ComputeMd5(request.Password);
        if (user.Password != passwordHash)
            return Unauthorized(new { error = "Şifre hatalı" }); // AÇIK: Enumeration!

        if (!user.IsActive)
            return Unauthorized(new { error = "Hesap aktif değil" });

        var token = GenerateWeakJwtToken(user);

        // AÇIK: Gereksiz sensitive bilgi response'da (email, fullname)
        return Ok(new LoginResponse
        {
            Token = token,
            UserId = user.Id,
            Username = user.Username,
            Role = user.Role,
            Email = user.Email,
            FullName = user.FullName
        });
    }

    // POST /api/auth/otp/send
    // AÇIK: Authentication yok — herkes herhangi bir userId için OTP isteyebilir
    // AÇIK: Rate limiting yok — OTP flood saldırısı mümkün
    [HttpPost("otp/send")]
    public async Task<IActionResult> SendOtp([FromBody] OtpSendRequest request)
    {
        var user = await _context.Users.FindAsync(request.UserId);
        if (user == null)
            return NotFound(new { error = "Kullanıcı bulunamadı" }); // AÇIK: Enumeration

        var otpCode = await _otpService.GenerateOtpAsync(request.UserId, request.Purpose);

        // AÇIK: OTP kodu direkt response'da dönüyor (SMS gitmeli!)
        // EXPLOIT: Response'u izleyen saldırgan OTP'yi görür
        return Ok(new { Message = "OTP gönderildi", OtpCode = otpCode, UserId = request.UserId });
    }

    // POST /api/auth/otp/verify
    // AÇIK: Rate limiting yok — brute-force açığı
    // EXPLOIT: Postman Runner ile 1000-9999 arası tüm değerleri dene (dakikalar içinde kırılır)
    // Modül 2.2 (OTP Güvenliği) için
    [HttpPost("otp/verify")]
    public async Task<IActionResult> VerifyOtp([FromBody] OtpVerifyRequest request)
    {
        var isValid = await _otpService.VerifyOtpAsync(request.UserId, request.OtpCode, request.Purpose);

        if (!isValid)
            return BadRequest(new { error = "OTP hatalı veya süresi geçmiş" });

        return Ok(new { Message = "OTP doğrulandı", UserId = request.UserId });
    }

    // POST /api/auth/forgot-password
    // AÇIK: Account enumeration (farklı hata mesajları)
    // AÇIK: Rate limiting yok — spam token üretimi mümkün
    // Modül 2.1 (Password Reset Güvenliği) için
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var token = await _passwordResetService.GenerateResetTokenAsync(request.Email);

        // AÇIK: Token direkt response'da — saldırgan intercept ederse şifre değiştirebilir
        // Güvenli: Token email ile gönderilmeli, response'da asla görünmemeli
        return Ok(new { Message = "Reset token oluşturuldu", ResetToken = token });
    }

    // POST /api/auth/reset-password
    // AÇIK: Rate limiting yok — token brute-force mümkün
    // AÇIK: Token expiry yok — eski token'lar çalışıyor
    // Modül 2.1 (Password Reset Güvenliği) için
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var success = await _passwordResetService.ResetPasswordAsync(request.Token, request.NewPassword);

        if (!success)
            return BadRequest(new { error = "Geçersiz token" });

        return Ok(new { Message = "Şifre başarıyla güncellendi" });
    }

    private static string GenerateWeakJwtToken(User user)
    {
        // AÇIK: 6 karakterlik hardcoded secret key ("secret")
        // AÇIK: ValidateIssuerSigningKey=false olduğundan imza doğrulanmıyor
        // AÇIK: Token süresi yok (no expiry) — sonsuza kadar geçerli
        // EXPLOIT: Algorithm:none ile imzasız token oluşturulup gönderilir
        // EXPLOIT: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxIiwicm9sZSI6ImFkbWluIn0.
        // CVSS: 9.1 (Critical) — Broken Authentication
        var key = Encoding.UTF8.GetBytes(JwtSecret);
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("userId", user.Id.ToString()),
                new Claim("role", user.Role),
                // AÇIK: Sensitive data in JWT payload — base64 decode edilebilir
                new Claim("email", user.Email),
                new Claim("balance", "see_account_endpoint")
            }),
            // AÇIK: Expiry yok — token sonsuza kadar geçerli
            // Güvenli: Expires = DateTime.UtcNow.AddMinutes(5)
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private static string ComputeMd5(string input)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLower();
    }
}
