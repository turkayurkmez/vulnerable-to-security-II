namespace VulnerableIssuerAPI.ThreatModeling
{
    public enum StrideCategory
    {
        Spoofing,
        Tampering,
        Repudiation,
        InformationDisclosure,
        DenialOfService,
        ElevationOfPrivilege
    }

    public enum RiskLevel
    {
        Low, // CVSS 0.1-3.9
        Medium,
        High,
        Critical // CVSS 9.0-10.0
    }

    public enum MitigationStatus
    {
        Open,
        InProgress,
        Mitigated,
        AcceptedRisk
    }
    public record Threat
    {
        public required  string Id { get; init; }
        public required string Component { get; init; } //hangi bileşen?

        public required StrideCategory Category { get; init; }
        public required string Description { get; init; }
        public required string AttackVector { get; init; } //Nasıl exploit edilir?

        public required RiskLevel Risk { get; init; }
        public required string Mitigation { get; init; } //Çözüm önerisi
        public MitigationStatus MitigationStatus { get; init; } = MitigationStatus.Open;

        public string? CvssScore { get; init; } //Opsiyonel: CVSS v3.1 base score (örn: "9.1 (Critical)")
        public string? PCIDSSRequirement { get; init; } //Opsiyonel: PCI DSS requirement reference (örn: "Requirement 3.2")



    }
}
