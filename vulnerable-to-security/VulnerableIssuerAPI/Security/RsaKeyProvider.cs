using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace VulnerableIssuerAPI.Security
{
    public static class RsaKeyProvider
    {
        //Güvenli: Uygulama başlatıldığında tek bir RSA anahtar çifti oluşturulur ve tüm uygulama boyunca kullanılır. Bu, her token için yeni anahtar oluşturulmasının önüne geçer ve performansı artırır.
        private static readonly RSA _privateKey;
        private static readonly RSA _publicKey;

        static RsaKeyProvider()
        {
            _privateKey = RSA.Create(2048); // 2048 bit anahtar uzunluğu güvenli kabul edilir
            var publicKeyParams= _privateKey.ExportRSAPublicKey();
            _publicKey = RSA.Create();
            _publicKey.ImportRSAPublicKey(publicKeyParams, out _);

        }

        public static RsaSecurityKey GetPrivateKey()
        {
            return new RsaSecurityKey(_privateKey);
        }

        public static RsaSecurityKey GetPublicKey()
        {
            return new RsaSecurityKey(_publicKey);
        }



    }
}
