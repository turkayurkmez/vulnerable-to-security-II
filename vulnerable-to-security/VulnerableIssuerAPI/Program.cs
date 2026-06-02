using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using VulnerableIssuerAPI.Data;
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
            // AÇIK: İmza doğrulanmıyor — herhangi bir key ile imzalanmış token geçerli
            ValidateIssuerSigningKey = false,
            // AÇIK: Issuer kontrolü yok — token'daki issuer önemsiz
            ValidateIssuer = false,
            // AÇIK: Audience kontrolü yok — herhangi bir audience kabul ediliyor
            ValidateAudience = false,
            // AÇIK: Expiry kontrolü yok — süresi dolmuş token'lar kabul ediliyor
            ValidateLifetime = false,
            // AÇIK: Algorithm confusion — "none" algoritması kabul ediliyor
            // EXPLOIT: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIzIiwicm9sZSI6ImFkbWluIn0.
            ValidAlgorithms = new[] { "HS256", "HS384", "HS512", "none" },
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret"))
        };
    });

builder.Services.AddAuthorization();

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

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// DataSeeder — Development ortamında veya --seed argümanı varsa çalışır
if (app.Environment.IsDevelopment() || args.Contains("--seed"))
{
    await DataSeeder.SeedAsync(app.Services);
}

app.Run();
