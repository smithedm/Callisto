using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.SecurityCenter;
using Callisto.Models;
using Callisto.Services;
using Microsoft.Extensions.Logging;

namespace Callisto.Scanners;

public class MonitoringSecurityScanner : ISecurityScanner
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<MonitoringSecurityScanner> _logger;

    public string ScannerName => "Monitoring & Threat Detection";
    public FindingCategory Category => FindingCategory.MonitoringAndThreatDetection;

    public MonitoringSecurityScanner(AzureAuthenticationService authService, ILogger<MonitoringSecurityScanner> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    public async Task<List<SecurityFinding>> ScanAsync(string subscriptionId, CancellationToken cancellationToken = default)
    {
        var findings = new List<SecurityFinding>();
        var armClient = await _authService.GetArmClientAsync();
        var subscription = armClient.GetSubscriptionResource(new Azure.Core.ResourceIdentifier($"/subscriptions/{subscriptionId}"));

        try
        {
            await CheckDefenderForCloud(subscription, findings, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during monitoring security scan");
        }

        return findings;
    }

    private async Task CheckDefenderForCloud(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var securityPricings = subscription.GetSecurityPricings();

            var criticalPlans = new[] { "VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "KeyVaults" };
            var recommendedPlans = new[] { "Containers", "Dns", "Arm", "OpenSourceRelationalDatabases" };

            await foreach (var pricing in securityPricings.GetAllAsync(cancellationToken: cancellationToken))
            {
                var planName = pricing.Data.Name;
                var pricingTier = pricing.Data.PricingTier?.ToString() ?? "Unknown";

                if (pricingTier == "Free" || pricingTier == "Unknown")
                {
                    var severity = Severity.Medium;
                    var description = $"Microsoft Defender for Cloud plan '{planName}' is not enabled.";

                    if (criticalPlans.Contains(planName))
                    {
                        severity = Severity.High;
                        description += " This plan provides critical security protections for your infrastructure.";
                    }
                    else if (recommendedPlans.Contains(planName))
                    {
                        severity = Severity.Medium;
                        description += " Enabling this plan would enhance your security posture.";
                    }
                    else
                    {
                        severity = Severity.Low;
                        description += " Consider enabling this plan for additional security coverage.";
                    }

                    findings.Add(new SecurityFinding
                    {
                        Title = $"Microsoft Defender Plan Not Enabled: {planName}",
                        Description = description,
                        Severity = severity,
                        Category = FindingCategory.MonitoringAndThreatDetection,
                        ResourceId = pricing.Id.ToString(),
                        ResourceName = planName,
                        ResourceType = "Microsoft.Security/pricings",
                        Recommendation = $"Enable Microsoft Defender for {planName} to get advanced threat protection, vulnerability assessments, and security recommendations.",
                        CanAutoRemediate = true,
                        RemediationAction = $"Enable Defender for {planName}",
                        Metadata = new Dictionary<string, string>
                        {
                            ["CurrentTier"] = pricingTier,
                            ["PlanName"] = planName
                        }
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check Defender for Cloud settings");
        }
    }
}
