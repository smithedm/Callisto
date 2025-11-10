using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Callisto.Models;
using Callisto.Services;
using Microsoft.Extensions.Logging;

namespace Callisto.Scanners;

public class ComplianceScanner : ISecurityScanner
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<ComplianceScanner> _logger;

    public string ScannerName => "Compliance & Governance";
    public FindingCategory Category => FindingCategory.ComplianceAndGovernance;

    public ComplianceScanner(AzureAuthenticationService authService, ILogger<ComplianceScanner> logger)
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
            await CheckResourceTags(subscription, findings, cancellationToken);
            await CheckResourceLocks(subscription, findings, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during compliance scan");
        }

        return findings;
    }

    private async Task CheckResourceTags(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var requiredTags = new[] { "Environment", "Owner", "CostCenter" };
            var resourcesWithoutTags = new List<string>();

            await foreach (var resource in subscription.GetGenericResourcesAsync(cancellationToken: cancellationToken))
            {
                if (resource.Data.Tags == null || resource.Data.Tags.Count == 0)
                {
                    findings.Add(new SecurityFinding
                    {
                        Title = "Resource Missing Tags",
                        Description = $"Resource '{resource.Data.Name}' has no tags. Tags are essential for cost management, governance, and compliance.",
                        Severity = Severity.Low,
                        Category = FindingCategory.ComplianceAndGovernance,
                        ResourceId = resource.Id.ToString(),
                        ResourceName = resource.Data.Name,
                        ResourceType = resource.Data.ResourceType.ToString(),
                        Recommendation = "Add tags such as Environment, Owner, CostCenter, and Application to enable proper resource management and cost tracking.",
                        CanAutoRemediate = false,
                        Metadata = new Dictionary<string, string>
                        {
                            ["Location"] = resource.Data.Location.ToString()
                        }
                    });
                }
                else
                {
                    var missingTags = requiredTags.Where(t => !resource.Data.Tags.ContainsKey(t)).ToList();
                    if (missingTags.Any())
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Resource Missing Required Tags",
                            Description = $"Resource '{resource.Data.Name}' is missing recommended tags: {string.Join(", ", missingTags)}",
                            Severity = Severity.Info,
                            Category = FindingCategory.ComplianceAndGovernance,
                            ResourceId = resource.Id.ToString(),
                            ResourceName = resource.Data.Name,
                            ResourceType = resource.Data.ResourceType.ToString(),
                            Recommendation = $"Add the following tags: {string.Join(", ", missingTags)} for better governance and cost allocation.",
                            CanAutoRemediate = false,
                            Metadata = new Dictionary<string, string>
                            {
                                ["MissingTags"] = string.Join(", ", missingTags),
                                ["ExistingTags"] = string.Join(", ", resource.Data.Tags.Keys)
                            }
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check resource tags");
        }
    }

    private async Task CheckResourceLocks(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var criticalResourceTypes = new[]
            {
                "Microsoft.Network/virtualNetworks",
                "Microsoft.Network/networkSecurityGroups",
                "Microsoft.KeyVault/vaults",
                "Microsoft.Sql/servers",
                "Microsoft.Storage/storageAccounts"
            };

            await foreach (var resource in subscription.GetGenericResourcesAsync(cancellationToken: cancellationToken))
            {
                if (!criticalResourceTypes.Contains(resource.Data.ResourceType.ToString()))
                    continue;

                try
                {
                    var locks = resource.GetManagementLocks();
                    var locksList = await locks.GetAllAsync(cancellationToken: cancellationToken).ToListAsync(cancellationToken);

                    if (!locksList.Any())
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Critical Resource Without Lock",
                            Description = $"Critical resource '{resource.Data.Name}' ({resource.Data.ResourceType}) has no resource lock. It can be accidentally deleted or modified.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.ComplianceAndGovernance,
                            ResourceId = resource.Id.ToString(),
                            ResourceName = resource.Data.Name,
                            ResourceType = resource.Data.ResourceType.ToString(),
                            Recommendation = "Apply a CanNotDelete or ReadOnly lock to protect critical resources from accidental deletion or modification.",
                            CanAutoRemediate = true,
                            RemediationAction = "Apply CanNotDelete lock to resource",
                            Metadata = new Dictionary<string, string>
                            {
                                ["Location"] = resource.Data.Location.ToString()
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to check locks for resource {ResourceName}", resource.Data.Name);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check resource locks");
        }
    }
}
