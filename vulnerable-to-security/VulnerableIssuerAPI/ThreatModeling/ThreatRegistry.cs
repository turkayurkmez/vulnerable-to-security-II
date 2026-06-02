namespace VulnerableIssuerAPI.ThreatModeling
{
    public static class ThreatRegistry
    {
        public static IReadOnlyList<Threat> All { get; } = new List<Threat>
        {
            // Threat'ler burada tanımlanır
            //Infrormation Disclosure
            new Threat
            {
                Id="THREAT-001",
                Component = "DebugController",
                Category = StrideCategory.InformationDisclosure,
                Description="Authentication olmayan debug endpoint'ler production'da erişilebilir",
                AttackVector="GET /_debug/info endpoint'ine herkes erişebilir",
                Mitigation ="Debog Controller production'da devre dışı bırakılmalı veya authentication ile korunmalı ([Authorize(Roles=Admin)]) önlemi alınabilir.",
                Risk = RiskLevel.Critical,
                MitigationStatus = MitigationStatus.Open,
                CvssScore = "10.0 (Critical)",
                PCIDSSRequirement = "PCI DSS Req:6.5.3 — Sensitive Data Exposure"
            },

             new Threat
            {
                Id="THREAT-002",
                Component = "AuthorizationService",
                Category = StrideCategory.Tampering,
                Description="Fiyat değeri negatif gönderilebilir",
                AttackVector="POST /transactions/authorize json body: { \"Amount\": -100 }",
                Mitigation ="Amount > 0 ve ayrıca maxAmount kuralları",
                Risk = RiskLevel.Critical,
                MitigationStatus = MitigationStatus.Mitigated,
                CvssScore = "9.0 (Critical)",
                PCIDSSRequirement = "PCI DSS Req:6.5.3 — Sensitive Data Exposure"
            },
               new Threat
            {
                Id="THREAT-003",
                Component = "AuthorizationService",
                Category = StrideCategory.Repudiation,
                Description="Audit-log kullanılmıyor! Kritik işlemler log'a alınmalı ve kaydedilmeli",
                AttackVector="POST /transactions/authorize",
                Mitigation ="Her kritik işlem için correlation ID. Serilog ve doğru bir SINK ile doğru formatta kadedilmeli.",
                Risk = RiskLevel.High,
                MitigationStatus = MitigationStatus.Open,
                CvssScore = "7.2",
                PCIDSSRequirement = "PCI DSS Req:6.5.3 — Sensitive Data Exposure"
            }






        }.AsReadOnly();

        // TODO 1.0: Kategori bazlı ve Risk seviyesine göre filtreleme, arama fonksiyonları eklenecek.  
        public static IEnumerable<Threat> ByCategory(StrideCategory category) => All.Where(t => t.Category == category);

        public static IEnumerable<Threat> ByRisk(RiskLevel risk) => All.Where(t => t.Risk == risk)
                                                                       .OrderByDescending(x=>x.Risk);


        
    }
}
