using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Resources;
using Callisto.Models;
using Callisto.Services;
using Microsoft.Extensions.Logging;

namespace Callisto.Scanners;

public class IamSecurityScanner : ISecurityScanner
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<IamSecurityScanner> _logger;

    public string ScannerName => "Identity & Access Management";
    public FindingCategory Category => FindingCategory.IdentityAndAccess;

    public IamSecurityScanner(AzureAuthenticationService authService, ILogger<IamSecurityScanner> logger)
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
            // Check for Owner role assignments
            await CheckOwnerRoleAssignments(subscription, findings, cancellationToken);

            // Check for wildcard permissions
            await CheckWildcardPermissions(subscription, findings, cancellationToken);

            // Check for custom role definitions with broad permissions
            await CheckCustomRoles(subscription, findings, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during IAM security scan");
        }

        return findings;
    }

    private async Task CheckOwnerRoleAssignments(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var roleAssignments = subscription.GetRoleAssignments();
            var ownerRoleDefinitionId = $"/subscriptions/{subscription.Id.SubscriptionId}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635";

            await foreach (var assignment in roleAssignments.GetAllAsync(cancellationToken: cancellationToken))
            {
                if (assignment.Data.RoleDefinitionId.ToString().Equals(ownerRoleDefinitionId, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new SecurityFinding
                    {
                        Title = "Owner Role Assignment Detected",
                        Description = $"The Owner role provides full access to all resources. Assignment found for principal: {assignment.Data.PrincipalId}",
                        Severity = Severity.High,
                        Category = FindingCategory.IdentityAndAccess,
                        ResourceId = assignment.Id.ToString(),
                        ResourceName = assignment.Data.Name,
                        ResourceType = "Microsoft.Authorization/roleAssignments",
                        Recommendation = "Review if Owner role is necessary. Consider using more restrictive built-in roles like Contributor, or custom roles with specific permissions. Follow principle of least privilege.",
                        CanAutoRemediate = false,
                        Metadata = new Dictionary<string, string>
                        {
                            ["PrincipalId"] = assignment.Data.PrincipalId.ToString(),
                            ["PrincipalType"] = assignment.Data.PrincipalType.ToString(),
                            ["Scope"] = assignment.Data.Scope
                        }
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check Owner role assignments");
        }
    }

    private async Task CheckWildcardPermissions(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var roleDefinitions = subscription.GetAuthorizationRoleDefinitions();

            await foreach (var roleDefinition in roleDefinitions.GetAllAsync(cancellationToken: cancellationToken))
            {
                if (roleDefinition.Data.RoleName.StartsWith("(PREVIEW)") ||
                    roleDefinition.Data.RoleType != "CustomRole")
                    continue;

                foreach (var permission in roleDefinition.Data.Permissions)
                {
                    var hasWildcardAction = permission.Actions.Any(a => a.Contains("*"));
                    var hasWildcardDataAction = permission.DataActions.Any(a => a.Contains("*"));

                    if (hasWildcardAction || hasWildcardDataAction)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Custom Role with Wildcard Permissions",
                            Description = $"Custom role '{roleDefinition.Data.RoleName}' contains wildcard (*) permissions which may grant excessive access.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.IdentityAndAccess,
                            ResourceId = roleDefinition.Id.ToString(),
                            ResourceName = roleDefinition.Data.RoleName,
                            ResourceType = "Microsoft.Authorization/roleDefinitions",
                            Recommendation = "Review custom role permissions and replace wildcards with specific actions required. This reduces the risk of unintended privilege escalation.",
                            CanAutoRemediate = false,
                            Metadata = new Dictionary<string, string>
                            {
                                ["RoleType"] = roleDefinition.Data.RoleType.ToString(),
                                ["HasWildcardActions"] = hasWildcardAction.ToString(),
                                ["HasWildcardDataActions"] = hasWildcardDataAction.ToString()
                            }
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check wildcard permissions");
        }
    }

    private async Task CheckCustomRoles(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var roleDefinitions = subscription.GetAuthorizationRoleDefinitions();
            var dangerousActions = new[]
            {
                "Microsoft.Authorization/*/write",
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Compute/*/write",
                "Microsoft.Compute/virtualMachines/runCommand/action"
            };

            await foreach (var roleDefinition in roleDefinitions.GetAllAsync(cancellationToken: cancellationToken))
            {
                if (roleDefinition.Data.RoleType != "CustomRole")
                    continue;

                foreach (var permission in roleDefinition.Data.Permissions)
                {
                    var hasDangerousActions = permission.Actions.Any(a =>
                        dangerousActions.Any(d => a.Equals(d, StringComparison.OrdinalIgnoreCase)));

                    if (hasDangerousActions)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Custom Role with Potentially Dangerous Permissions",
                            Description = $"Custom role '{roleDefinition.Data.RoleName}' has permissions that could be abused for privilege escalation or lateral movement.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.IdentityAndAccess,
                            ResourceId = roleDefinition.Id.ToString(),
                            ResourceName = roleDefinition.Data.RoleName,
                            ResourceType = "Microsoft.Authorization/roleDefinitions",
                            Recommendation = "Review the necessity of write permissions on Authorization resources and VM runCommand actions. These can be used for privilege escalation.",
                            CanAutoRemediate = false
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check custom roles");
        }
    }
}
