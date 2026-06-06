using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableIssuerAPI.Services
{

    //GÜVENLİ: immutable record oluştur. parmak izi bir kez oluşturulduktan sonra değiştirilemez.

    public record DeviceFingerprint(string Hash, string UserAgent, string Language, string IPAddress, DateTime CreatedAt);

    public enum DeviceTrustLevel
    {
        Trusted, //Hash daha önce görülmüş ve güvenilir olarak işaretlenmiş cihazlar
        New, // Hash daha önce görülmemiş yeni cihazlar (ilk kez görülüyor)
        Suspicious // 1 saat içinde 3'den fazla farklı hash gözüken cihazlar (potansiyel olarak şüpheli)

    }

    public interface IDeviceFingerPrintingService
    {
        DeviceFingerprint ExtractFingerPrinting(HttpContext httpContext);
        Task<DeviceTrustLevel> EvaluateDeviceAsync(int userId, DeviceFingerprint deviceFingerprint);
        Task RegisterDeviceAsync(int userId, DeviceFingerprint deviceFingerprint);
    }

    public class DeviceFingerPrintingService : IDeviceFingerPrintingService
    {
        private readonly ConcurrentDictionary<int, List<RegisteredDevice>> _deviceRegistry = new();
        public DeviceFingerPrintingService()
        {
           
        }
        public DeviceFingerprint ExtractFingerPrinting(HttpContext httpContext)
        {
            // Kullanıcıdan gelen bilgileri kullanarak parmak izi oluştur
            var headers = httpContext.Request.Headers;
            var userAgent = headers.UserAgent.ToString();
            var language = headers.AcceptLanguage.ToString();
            var encoding = headers.AcceptEncoding.ToString();




            var ipAddress = headers["X-Forwarded-For"].FirstOrDefault() ?? httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"; 

            var maskedIpAddress = MaskIPAddress(ipAddress);

            // Basit bir hash oluşturma (güvenli değil, sadece örnek amaçlı)
            var hashInput = $"{userAgent}|{language}|{ipAddress}";
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(hashInput)));
            return new DeviceFingerprint(hash, userAgent, language, maskedIpAddress, DateTime.UtcNow);
        }

        private string MaskIPAddress(string ipAddress)
        {
            // IP adresini maskeleme (örneğin, son okteti gizleme)
            var segments = ipAddress.Split('.');
            if (segments.Length == 4)
            {
                segments[3] = "xxx";
                return string.Join('.', segments);
            }
            return ipAddress; // IPv6 veya geçersiz formatta ise olduğu gibi döndür
        }
        public  Task<DeviceTrustLevel> EvaluateDeviceAsync(int userId, DeviceFingerprint deviceFingerprint)
        {
            if (!_deviceRegistry.TryGetValue(userId, out var devices))
            {
                return Task.FromResult(DeviceTrustLevel.New); // Kullanıcıya ait cihaz kaydı yok, yeni cihaz                
            }

            lock (devices)
            {
                //Hash daha önce görülmüş mü kontrol et
                if (devices.Any(d=>d.Hash == deviceFingerprint.Hash))
                {
                    return Task.FromResult(DeviceTrustLevel.Trusted);
                }

                var recentHashes = devices.Where(d => (DateTime.UtcNow - d.RegisteredAt).TotalHours < 1).Select(d => d.Hash).Distinct().Count();

                return Task.FromResult(recentHashes >= 3 ? DeviceTrustLevel.Suspicious : DeviceTrustLevel.New);

            }
        }
        public  Task RegisterDeviceAsync(int userId, DeviceFingerprint deviceFingerprint)
        {
            var devices = _deviceRegistry.GetOrAdd(userId,_ => new List<RegisteredDevice>());

            lock (devices)
            {
                var existing = devices.FirstOrDefault(d => d.Hash == deviceFingerprint.Hash);
                if (existing != null)
                {
                    existing.LastSeenAt = DateTime.UtcNow;
                   return Task.CompletedTask;
                }

                //Sınırsız büyümesin. Maks 5 cihaz olsun:
                if (devices.Count >= 5)
                {
                    devices.Remove(devices.OrderBy(d=>d.LastSeenAt).First()); // En eski cihazı kaldır
                }

                devices.Add(new RegisteredDevice
                {
                    Hash = deviceFingerprint.Hash,
                    RegisteredAt = DateTime.UtcNow,
                    LastSeenAt = DateTime.UtcNow
                });
            }

            return Task.CompletedTask;
        }
    }

    public class RegisteredDevice
    {
        public required string Hash { get; set; }
        public DateTime RegisteredAt { get; set; }
        public DateTime LastSeenAt { get; set; }
    }
}
