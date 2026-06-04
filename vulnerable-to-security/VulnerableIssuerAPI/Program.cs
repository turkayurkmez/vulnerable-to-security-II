using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Security;
using VulnerableIssuerAPI.SeedData;
using VulnerableIssuerAPI.Services;

var builder = WebApplication.CreateBuilder(args);

// ============================================================
// AÇIK: Güvensiz JWT konfigürasyonu
// Modül 2.4 (JWT Implementasyonu) için
// ============================================================
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = RsaKeyProvider.GetPublicKey(),
            ValidIssuer = "api.softtech.com",

            ValidateIssuer = true,

            ValidateAudience = true,
            ValidAudience = "client.softtech.com",

            ValidateLifetime = true,


            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },

            ClockSkew = TimeSpan.Zero //ClockSkew'in amacı, token süresinin tam olarak dolduğu anda geçersiz sayılmasını önlemek için küçük bir tolerans sağlamaktır. Ancak burada sıfır yaparak, token süresi dolar dolmaz geçersiz sayılmasını sağlıyoruz. Bu, token'ın süresi dolduktan sonra hemen reddedilmesini sağlar ve güvenliği artırır.
        };
    });

builder.Services.AddMemoryCache();

builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(options =>
{
    // TODO 2: otp-per-account ve otp-per-ip limitleri ekle
    options.AddPolicy("otp-per-account", httpContext => RateLimitPartition.GetSlidingWindowLimiter(
        partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        factory: _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = 5, // Her hesap için 5 OTP doğrulama denemesi
            Window = TimeSpan.FromMinutes(5), // 55 dakika boyunca geçerli
            SegmentsPerWindow = 5,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        }) );

    options.AddPolicy("otp-per-ip", httpContxt => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: httpContxt.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10, // Her IP adresi için dakikada 100 OTP doğrulama denemesi
            Window = TimeSpan.FromMinutes(5),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        }));

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context,_) =>
    {
        context.HttpContext.Response.Headers["Retry-After"] = "300"; // 5 dakika sonra tekrar deneyin
        await Task.CompletedTask;
    };


});

// ============================================================
// AÇIK: CORS tamamen açık — her origin, her method, her header
// Modül 4.4 (Architecture) için
// ============================================================
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
        // AÇIK: AllowCredentials() kaldırıldı, AllowAnyOrigin ile birleşince CSRF riski
    });
});

// EF Core + SQLite
builder.Services.AddDbContext<VulnerableDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default")));

// Services
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddScoped<PasswordResetService>();

builder.Services.AddControllers();

// ============================================================
// AÇIK: Swagger hem Development hem Production'da açık (koşulsuz)
// Modül 4.4 (Architecture) için
// ============================================================
// builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen(c =>
// {
//     c.SwaggerDoc("v1", new() { Title = "VulnerableIssuerAPI — Eğitim Amaçlı", Version = "v1",
//         Description = "⚠️ UYARI: Bu API kasıtlı güvenlik açıkları içermektedir. SADECE eğitim amaçlıdır!" });
// });

builder.Services.AddOpenApi();

var app = builder.Build();

// ============================================================
// AÇIK: Global exception handler — stack trace client'a gönderiliyor
// Modül 4.2 (Error Handling & Information Disclosure) için
// ============================================================
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";

        var exceptionFeature = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();
        if (exceptionFeature != null)
        {
            var ex = exceptionFeature.Error;
            // AÇIK: Stack trace ve inner exception detayları client'a gönderiliyor
            // EXPLOIT: Internal sistemler, DB query yapısı, dosya yolları açığa çıkıyor
            await context.Response.WriteAsJsonAsync(new
            {
                Error = ex.Message,
                StackTrace = ex.StackTrace,       // AÇIK: Stack trace
                InnerException = ex.InnerException?.Message,
                Type = ex.GetType().FullName       // AÇIK: Exception type
            });
        }
    });
});

// AÇIK: HTTPS redirect yok — HTTP üzerinden gelen veriler şifrelenmeden taşınıyor
// Güvenli: app.UseHttpsRedirection();
// app.UseHttpsRedirection(); // AÇIK: Kasıtlı olarak yorum satırında

// AÇIK: Security headers yok
// Güvenli olurdu:
// app.Use(async (ctx, next) => { ctx.Response.Headers["X-Content-Type-Options"] = "nosniff"; ... });

// AÇIK: Rate limiting yok — brute-force, DoS saldırılarına açık
// Modül 3.4 (Rate Limiting & DoS Protection) için

app.UseCors();

// Swagger hem dev hem prod'da açık
// app.UseSwagger();
// app.UseSwaggerUI(c =>
// {
//     c.SwaggerEndpoint("/swagger/v1/swagger.json", "VulnerableIssuerAPI v1");
// });

if (app.Environment.IsDevelopment()) // AÇIK: Koşulsuz Swagger açma
{
    app.MapOpenApi();
    app.MapScalarApiReference(option =>
    {
        option.Title = "VulnerableIssuerAPI — API Reference";
        option.Theme =  ScalarTheme.DeepSpace;  // AÇIK: Dark theme, bazı güvenlik açıklarını daha görünür kılabilir
    });
}

// Scalar API reference (ek UI)
//app.MapScalarApiReference();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// DataSeeder — Development ortamında veya --seed argümanı varsa çalışır
if (app.Environment.IsDevelopment() || args.Contains("--seed"))
{
    await DataSeeder.SeedAsync(app.Services);
}

app.Run();
