namespace Callisto.Models;

public enum Severity
{
    Critical,
    High,
    Medium,
    Low,
    Info
}

public enum FindingCategory
{
    IdentityAndAccess,
    NetworkSecurity,
    DataProtection,
    MonitoringAndThreatDetection,
    ComplianceAndGovernance,
    ResourceSecurity
}

public class SecurityFinding
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public FindingCategory Category { get; set; }
    public string ResourceId { get; set; } = string.Empty;
    public string ResourceName { get; set; } = string.Empty;
    public string ResourceType { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public bool CanAutoRemediate { get; set; }
    public string? RemediationAction { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
}

public class ScanResult
{
    public string SubscriptionId { get; set; } = string.Empty;
    public string SubscriptionName { get; set; } = string.Empty;
    public DateTime ScanStartTime { get; set; }
    public DateTime ScanEndTime { get; set; }
    public List<SecurityFinding> Findings { get; set; } = new();
    public Dictionary<Severity, int> FindingsBySeverity { get; set; } = new();
    public Dictionary<FindingCategory, int> FindingsByCategory { get; set; } = new();
    public int TotalFindings => Findings.Count;
    public int RemediableFindings => Findings.Count(f => f.CanAutoRemediate);
}

public class RemediationResult
{
    public string FindingId { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime RemediatedAt { get; set; } = DateTime.UtcNow;
    public string? Error { get; set; }
}
