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
using Microsoft.AspNetCore.RateLimiting;
using VulnerableIssuerAPI.Security;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    // AÇIK: Weak JWT secret — hardcoded, sadece 6 karakter
    // EXPLOIT: hashcat ile saniyeler içinde kırılabilir
    // CVSS: 9.1 (Critical) — Broken Authentication
    // Modül 2.4 (JWT Implementasyonu) için
    private const string JwtSecret = "secret-for-demo-and-this-data-must-be-128-bit";

    private readonly VulnerableDbContext _context;
    private readonly OtpService _otpService;
    private readonly PasswordResetService _passwordResetService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(VulnerableDbContext context, OtpService otpService, PasswordResetService passwordResetService, ILogger<AuthController> logger)
    {
        _context = context;
        _otpService = otpService;
        _passwordResetService = passwordResetService;
        _logger = logger;
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

        //var passwordHash = ComputeMd5(request.Password);
        if (!BCrypt.Net.BCrypt.Verify(request.Password,user.Password))
            return Unauthorized(new { error = "Şifre hatalı" }); // AÇIK: Enumeration!

        if (!user.IsActive)
            return Unauthorized(new { error = "Hesap aktif değil" });


        //demo amaçlı MFA token'ı burada oluşturyoruz. MFA yani Çok Faktörlü Kimlik Doğrulama, kullanıcıların kimliklerini doğrulamak için birden fazla yöntem kullanmalarını gerektiren bir güvenlik önlemidir. Genellikle, kullanıcı adı ve şifre gibi birinci faktörün yanı sıra, telefonlarına gönderilen bir kod veya bir uygulama tarafından üretilen tek kullanımlık şifre gibi ikinci bir faktör de gerektirir. Bu, saldırganların sadece şifreyi ele geçirmeleri durumunda bile hesaba erişmelerini zorlaştırır.
        //Olası tehditler: Session fixation, token hijacking, brute-force MFA bypass.


        var pendingMFAToken = generateMFAToken(user.Id);

        var token = GenerateSecureJwtToken(user);

        var pendingKey = $"mfa_pending:{pendingMFAToken}";

        //Aslında bu key cache'de saklanmalı, burada sadece simülasyon amaçlı olarak logluyoruz



        // AÇIK: Gereksiz sensitive bilgi response'da (email, fullname)
        var response = new LoginResponse
        {
            Token = token,
            UserId = user.Id,
            Username = user.Username,
            Role = user.Role,
            Email = user.Email,
            FullName = user.FullName
        };
        return Ok(new {response= response, pendingKey=pendingKey, message="MFA key bekleniyor."});
    }

    [HttpPost("verify_mfa")]
    public async Task<IActionResult> VerifyMfa()
    {
        /*
         * Pending token kontrolü - bypass token reddetme senaryosu.
         */
        await Task.Delay(100);
        return Ok();
    }

    private string generateMFAToken(int id)
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return $"{id}_{Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd("=")}";
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
        _logger.LogInformation("[SMS Simülasyonu]: {code}", otpCode);
        return Ok(new { Message = "OTP gönderildi" });
    }

    // POST /api/auth/otp/verify
    // AÇIK: Rate limiting yok — brute-force açığı
    // EXPLOIT: Postman Runner ile 1000-9999 arası tüm değerleri dene (dakikalar içinde kırılır)
    // Modül 2.2 (OTP Güvenliği) için
    [EnableRateLimiting("otp-per-account")]  
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
        return Ok(new { Message = "Eğer eposta kayıtlıysa, sıfırlama talimatları gönderildi", ResetToken = token });
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

    private static string GenerateSecureJwtToken(User user)
    {
        // AÇIK: 6 karakterlik hardcoded secret key ("secret")
        // AÇIK: ValidateIssuerSigningKey=false olduğundan imza doğrulanmıyor
        // AÇIK: Token süresi yok (no expiry) — sonsuza kadar geçerli
        // EXPLOIT: Algorithm:none ile imzasız token oluşturulup gönderilir
        // EXPLOIT: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxIiwicm9sZSI6ImFkbWluIn0.
        // CVSS: 9.1 (Critical) — Broken Authentication
       // var key = Encoding.UTF8.GetBytes(JwtSecret);
        var tokenHandler = new JwtSecurityTokenHandler();

        var signingCredentials = new SigningCredentials(
            RsaKeyProvider.GetPrivateKey(),
            SecurityAlgorithms.RsaSha256);




        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id.ToString()),
                new Claim("role", user.Role),
                // AÇIK: Sensitive data in JWT payload — base64 decode edilebilir
               // new Claim("email", user.Email),
                //new Claim("balance", "see_account_endpoint")
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddMinutes(10),
            NotBefore = DateTime.UtcNow,
            IssuedAt = DateTime.UtcNow,

            // AÇIK: Expiry yok — token sonsuza kadar geçerli
            // Güvenli: Expires = DateTime.UtcNow.AddMinutes(5)
            SigningCredentials = signingCredentials,
            Issuer = "api.softtech.com",
            Audience= "client.softtech.com",
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
