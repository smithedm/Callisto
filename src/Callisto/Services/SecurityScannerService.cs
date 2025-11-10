using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Callisto.Models;
using Callisto.Scanners;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace Callisto.Services;

public class SecurityScannerService
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<SecurityScannerService> _logger;
    private readonly List<ISecurityScanner> _scanners;

    public SecurityScannerService(
        AzureAuthenticationService authService,
        ILogger<SecurityScannerService> logger,
        IEnumerable<ISecurityScanner> scanners)
    {
        _authService = authService;
        _logger = logger;
        _scanners = scanners.ToList();
    }

    public async Task<ScanResult> ScanSubscriptionAsync(
        string subscriptionId,
        CallistoConfiguration config,
        CancellationToken cancellationToken = default)
    {
        var startTime = DateTime.UtcNow;
        _logger.LogInformation("Starting security scan for subscription: {SubscriptionId}", subscriptionId);

        var armClient = await _authService.GetArmClientAsync();
        var subscription = armClient.GetSubscriptionResource(new Azure.Core.ResourceIdentifier($"/subscriptions/{subscriptionId}"));
        var subscriptionData = await subscription.GetAsync(cancellationToken);

        var result = new ScanResult
        {
            SubscriptionId = subscriptionId,
            SubscriptionName = subscriptionData.Value.Data.DisplayName ?? subscriptionId,
            ScanStartTime = startTime
        };

        AnsiConsole.MarkupLine($"[bold blue]Scanning subscription:[/] {result.SubscriptionName} ({subscriptionId})");
        AnsiConsole.WriteLine();

        var enabledScanners = GetEnabledScanners(config.ScanOptions);

        await AnsiConsole.Progress()
            .AutoRefresh(true)
            .AutoClear(false)
            .HideCompleted(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new SpinnerColumn(),
            })
            .StartAsync(async ctx =>
            {
                foreach (var scanner in enabledScanners)
                {
                    var task = ctx.AddTask($"[green]{scanner.ScannerName}[/]");
                    task.IsIndeterminate = true;

                    try
                    {
                        _logger.LogInformation("Running scanner: {ScannerName}", scanner.ScannerName);
                        var findings = await scanner.ScanAsync(subscriptionId, cancellationToken);

                        var filteredFindings = findings
                            .Where(f => config.ScanOptions.MinimumSeverity.Contains(f.Severity))
                            .ToList();

                        result.Findings.AddRange(filteredFindings);

                        task.Value = 100;
                        task.StopTask();

                        var criticalCount = filteredFindings.Count(f => f.Severity == Severity.Critical);
                        var highCount = filteredFindings.Count(f => f.Severity == Severity.High);

                        if (criticalCount > 0 || highCount > 0)
                        {
                            AnsiConsole.MarkupLine($"  [red]✗[/] {scanner.ScannerName}: {filteredFindings.Count} findings ([red]{criticalCount} critical[/], [orange1]{highCount} high[/])");
                        }
                        else if (filteredFindings.Count > 0)
                        {
                            AnsiConsole.MarkupLine($"  [yellow]![/] {scanner.ScannerName}: {filteredFindings.Count} findings");
                        }
                        else
                        {
                            AnsiConsole.MarkupLine($"  [green]✓[/] {scanner.ScannerName}: No issues found");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error running scanner: {ScannerName}", scanner.ScannerName);
                        AnsiConsole.MarkupLine($"  [red]✗[/] {scanner.ScannerName}: Error - {ex.Message}");
                        task.StopTask();
                    }
                }
            });

        result.ScanEndTime = DateTime.UtcNow;

        // Calculate statistics
        foreach (var finding in result.Findings)
        {
            if (!result.FindingsBySeverity.ContainsKey(finding.Severity))
                result.FindingsBySeverity[finding.Severity] = 0;
            result.FindingsBySeverity[finding.Severity]++;

            if (!result.FindingsByCategory.ContainsKey(finding.Category))
                result.FindingsByCategory[finding.Category] = 0;
            result.FindingsByCategory[finding.Category]++;
        }

        _logger.LogInformation("Security scan completed. Found {Count} findings", result.TotalFindings);
        return result;
    }

    private List<ISecurityScanner> GetEnabledScanners(ScanOptions options)
    {
        return _scanners.Where(s => IsScannerEnabled(s, options)).ToList();
    }

    private bool IsScannerEnabled(ISecurityScanner scanner, ScanOptions options)
    {
        return scanner.Category switch
        {
            FindingCategory.IdentityAndAccess => options.EnableIamScanner,
            FindingCategory.NetworkSecurity => options.EnableNetworkScanner,
            FindingCategory.DataProtection => options.EnableDataProtectionScanner,
            FindingCategory.MonitoringAndThreatDetection => options.EnableMonitoringScanner,
            FindingCategory.ComplianceAndGovernance => options.EnableComplianceScanner,
            FindingCategory.ResourceSecurity => options.EnableResourceScanner,
            _ => true
        };
    }
}
