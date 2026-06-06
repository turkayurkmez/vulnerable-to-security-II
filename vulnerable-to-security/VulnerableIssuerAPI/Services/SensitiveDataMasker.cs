namespace VulnerableIssuerAPI.Services
{
    public static class SensitiveDataMasker

    {
        // Güvenli: Kart numarası gibi hassas bilgileri maskeleme. İlk 6 ve son 4 hane açık, geri kalan yıldız ile gizlenir.
        public static string MaskPan(string pan)
        {
            if (string.IsNullOrEmpty(pan) || pan.Length < 10)
                return "****";
            return pan[..6] + new string('*', pan.Length - 10) + pan[^4..];
        }

        public static string MaskCvv(string cvv) => "***"; // CVV hiçbir zaman saklanmamalı ve iletilmemeli (PCI DSS Requirement 3.2)

        public static string MaskOtp(string otp) => $"[OTP:{otp?.Length ?? 0}-digit, value=[REDACTED]]"; // OTP'ler de maskeleme ile gizlenmeli, loglarda veya response'larda açıkta gösterilmemeli

        public static string Redacted(string value) => "[REDACTED]";


    }
}
