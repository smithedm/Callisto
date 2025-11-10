using Azure.ResourceManager;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Resources;
using Callisto.Models;
using Callisto.Services;
using Microsoft.Extensions.Logging;

namespace Callisto.Scanners;

public class NetworkSecurityScanner : ISecurityScanner
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<NetworkSecurityScanner> _logger;

    public string ScannerName => "Network Security";
    public FindingCategory Category => FindingCategory.NetworkSecurity;

    public NetworkSecurityScanner(AzureAuthenticationService authService, ILogger<NetworkSecurityScanner> logger)
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
            await CheckNetworkSecurityGroups(subscription, findings, cancellationToken);
            await CheckPublicIpAddresses(subscription, findings, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during network security scan");
        }

        return findings;
    }

    private async Task CheckNetworkSecurityGroups(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var nsgs = resourceGroup.GetNetworkSecurityGroups();

                await foreach (var nsg in nsgs.GetAllAsync(cancellationToken: cancellationToken))
                {
                    // Check for overly permissive inbound rules
                    foreach (var rule in nsg.Data.SecurityRules)
                    {
                        if (rule.Direction != Azure.ResourceManager.Network.Models.SecurityRuleDirection.Inbound)
                            continue;

                        if (rule.Access != Azure.ResourceManager.Network.Models.SecurityRuleAccess.Allow)
                            continue;

                        var isFromAnySource = rule.SourceAddressPrefix == "*" || rule.SourceAddressPrefix == "0.0.0.0/0" || rule.SourceAddressPrefix == "Internet";
                        var isToAnyDestination = rule.DestinationAddressPrefix == "*" || rule.DestinationAddressPrefix == "0.0.0.0/0";

                        if (isFromAnySource)
                        {
                            var severity = Severity.Medium;
                            var dangerousPorts = new[] { "22", "3389", "1433", "3306", "5432", "27017", "6379" };

                            // Check if rule allows dangerous ports
                            var rulePort = rule.DestinationPortRange;
                            if (!string.IsNullOrEmpty(rulePort) && dangerousPorts.Contains(rulePort))
                            {
                                severity = Severity.Critical;
                            }
                            else if (rulePort == "*" || rulePort == "0-65535")
                            {
                                severity = Severity.High;
                            }

                            findings.Add(new SecurityFinding
                            {
                                Title = "NSG Rule Allows Inbound Traffic from Internet",
                                Description = $"Network Security Group '{nsg.Data.Name}' has rule '{rule.Name}' allowing inbound traffic from the Internet (0.0.0.0/0 or *) to port(s) {rulePort}.",
                                Severity = severity,
                                Category = FindingCategory.NetworkSecurity,
                                ResourceId = nsg.Id.ToString(),
                                ResourceName = nsg.Data.Name,
                                ResourceType = "Microsoft.Network/networkSecurityGroups",
                                Recommendation = severity == Severity.Critical
                                    ? $"CRITICAL: Management/database ports should never be exposed to the Internet. Restrict source to specific IP ranges or use Azure Bastion/VPN for management access."
                                    : "Restrict inbound rules to specific source IP addresses or ranges. Avoid using 0.0.0.0/0 or * as source.",
                                CanAutoRemediate = false,
                                RemediationAction = $"Update NSG rule '{rule.Name}' to restrict source address",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["RuleName"] = rule.Name,
                                    ["Priority"] = rule.Priority.ToString(),
                                    ["SourceAddressPrefix"] = rule.SourceAddressPrefix ?? "N/A",
                                    ["DestinationPortRange"] = rulePort ?? "N/A",
                                    ["Protocol"] = rule.Protocol.ToString(),
                                    ["ResourceGroup"] = resourceGroup.Data.Name
                                }
                            });
                        }
                    }

                    // Check for default security rules only (no custom rules)
                    if (!nsg.Data.SecurityRules.Any())
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "NSG with No Custom Security Rules",
                            Description = $"Network Security Group '{nsg.Data.Name}' has no custom security rules defined, relying only on default rules.",
                            Severity = Severity.Low,
                            Category = FindingCategory.NetworkSecurity,
                            ResourceId = nsg.Id.ToString(),
                            ResourceName = nsg.Data.Name,
                            ResourceType = "Microsoft.Network/networkSecurityGroups",
                            Recommendation = "Review if this NSG needs custom rules. Default rules may not provide adequate protection for your workload.",
                            CanAutoRemediate = false,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check network security groups");
        }
    }

    private async Task CheckPublicIpAddresses(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var publicIps = resourceGroup.GetPublicIPAddresses();

                await foreach (var publicIp in publicIps.GetAllAsync(cancellationToken: cancellationToken))
                {
                    // Check if public IP is not associated with any resource
                    if (publicIp.Data.IPConfiguration == null && publicIp.Data.NatGateway == null)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Unattached Public IP Address",
                            Description = $"Public IP address '{publicIp.Data.Name}' is not associated with any resource but still consuming resources and potentially billable.",
                            Severity = Severity.Low,
                            Category = FindingCategory.NetworkSecurity,
                            ResourceId = publicIp.Id.ToString(),
                            ResourceName = publicIp.Data.Name,
                            ResourceType = "Microsoft.Network/publicIPAddresses",
                            Recommendation = "Remove unused public IP addresses to reduce attack surface and costs.",
                            CanAutoRemediate = true,
                            RemediationAction = "Delete unattached public IP address",
                            Metadata = new Dictionary<string, string>
                            {
                                ["IPAddress"] = publicIp.Data.IPAddress ?? "Not allocated",
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check public IP addresses");
        }
    }
}
