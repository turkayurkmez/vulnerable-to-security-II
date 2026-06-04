using Microsoft.Extensions.Caching.Memory;
using System.Security.Cryptography;

namespace VulnerableIssuerAPI.Services
{
    public class MfaService
    {
        private readonly IMemoryCache _cache;

        public MfaService(IMemoryCache cache)
        {
            _cache = cache;
        }

        //GÜVENLİ: Güçlü rastgele kodlar üretir, her kod tek kullanımlık ve benzersizdir

        public List<string> GenerateBackupCodes(int count = 8)        
        {
            var codes = new List<string>();
            for (int i = 0; i < count; i++)
            {
                var bytes = new byte[6];
                RandomNumberGenerator.Fill(bytes);
                codes.Add(Convert.ToHexStringLower(bytes));
            }
            return codes;

        }

        public List<string> HashBackupCodes(List<string> codes)
        {
            //Bcrypt yerine Sha256 + salt kullanarak hashleme yapabiliriz. Ama Production ortamında bcrypt veya argon2 gibi güçlü bir algoritma tercih edilir.
            return codes.Select(code => BCrypt.Net.BCrypt.HashPassword(code)).ToList();
        }

        public bool ValidateBackupCode(string inputCode, List<string> hashedCodes)
        {
            //GÜVENLİ: Kullanıcı tarafından girilen kodu hashleyip, hashlenmiş kodlarla karşılaştırır. Doğruysa kodu geçersiz kılar (tek kullanımlık).
            foreach (var hashedCode in hashedCodes)
            {
                if (BCrypt.Net.BCrypt.Verify(inputCode, hashedCode))
                {
                    // Kod doğrulandıktan sonra geçersiz kılınır
                    hashedCodes.Remove(hashedCode);
                    return true;
                }
            }
            return false;
        }

    }
}
