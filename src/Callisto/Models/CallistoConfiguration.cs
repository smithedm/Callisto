namespace Callisto.Models;

public class CallistoConfiguration
{
    public string? SubscriptionId { get; set; }
    public string? TenantId { get; set; }
    public OutputFormat OutputFormat { get; set; } = OutputFormat.Console;
    public string? OutputPath { get; set; }
    public bool VerboseLogging { get; set; }
    public ScanOptions ScanOptions { get; set; } = new();
}

public class ScanOptions
{
    public bool EnableIamScanner { get; set; } = true;
    public bool EnableNetworkScanner { get; set; } = true;
    public bool EnableDataProtectionScanner { get; set; } = true;
    public bool EnableMonitoringScanner { get; set; } = true;
    public bool EnableComplianceScanner { get; set; } = true;
    public bool EnableResourceScanner { get; set; } = true;
    public List<Severity> MinimumSeverity { get; set; } = new() { Severity.Info, Severity.Low, Severity.Medium, Severity.High, Severity.Critical };
}

public enum OutputFormat
{
    Console,
    Json,
    Html,
    Csv
}
