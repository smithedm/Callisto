using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Storage;
using Callisto.Models;
using Callisto.Services;
using Microsoft.Extensions.Logging;

namespace Callisto.Scanners;

public class DataProtectionScanner : ISecurityScanner
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<DataProtectionScanner> _logger;

    public string ScannerName => "Data Protection";
    public FindingCategory Category => FindingCategory.DataProtection;

    public DataProtectionScanner(AzureAuthenticationService authService, ILogger<DataProtectionScanner> logger)
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
            await CheckStorageAccountSecurity(subscription, findings, cancellationToken);
            await CheckKeyVaultSecurity(subscription, findings, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during data protection scan");
        }

        return findings;
    }

    private async Task CheckStorageAccountSecurity(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var storageAccounts = resourceGroup.GetStorageAccounts();

                await foreach (var storageAccount in storageAccounts.GetAllAsync(cancellationToken: cancellationToken))
                {
                    var data = storageAccount.Data;

                    // Check if HTTPS only is enforced
                    if (!data.EnableHttpsTrafficOnly.HasValue || !data.EnableHttpsTrafficOnly.Value)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Storage Account Allows HTTP Traffic",
                            Description = $"Storage account '{data.Name}' does not enforce HTTPS-only traffic. Data can be transmitted unencrypted.",
                            Severity = Severity.High,
                            Category = FindingCategory.DataProtection,
                            ResourceId = storageAccount.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Storage/storageAccounts",
                            Recommendation = "Enable 'Secure transfer required' to enforce HTTPS for all connections to storage account.",
                            CanAutoRemediate = true,
                            RemediationAction = "Enable HTTPS-only traffic",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name,
                                ["Location"] = data.Location.ToString()
                            }
                        });
                    }

                    // Check minimum TLS version
                    if (data.MinimumTlsVersion.HasValue &&
                        (data.MinimumTlsVersion.Value.ToString() == "TLS1_0" ||
                         data.MinimumTlsVersion.Value.ToString() == "TLS1_1"))
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Storage Account Uses Outdated TLS Version",
                            Description = $"Storage account '{data.Name}' allows TLS 1.0 or 1.1, which have known security vulnerabilities.",
                            Severity = Severity.High,
                            Category = FindingCategory.DataProtection,
                            ResourceId = storageAccount.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Storage/storageAccounts",
                            Recommendation = "Set minimum TLS version to 1.2 or higher to protect against protocol downgrade attacks.",
                            CanAutoRemediate = true,
                            RemediationAction = "Update minimum TLS version to 1.2",
                            Metadata = new Dictionary<string, string>
                            {
                                ["CurrentTlsVersion"] = data.MinimumTlsVersion.Value.ToString(),
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check for public blob access
                    if (data.AllowBlobPublicAccess.HasValue && data.AllowBlobPublicAccess.Value)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Storage Account Allows Public Blob Access",
                            Description = $"Storage account '{data.Name}' allows public anonymous access to blobs, which may expose sensitive data.",
                            Severity = Severity.High,
                            Category = FindingCategory.DataProtection,
                            ResourceId = storageAccount.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Storage/storageAccounts",
                            Recommendation = "Disable public blob access unless absolutely necessary. Use SAS tokens or Azure AD authentication instead.",
                            CanAutoRemediate = true,
                            RemediationAction = "Disable public blob access",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check if storage account key access is allowed (should use Azure AD when possible)
                    if (data.AllowSharedKeyAccess.HasValue && data.AllowSharedKeyAccess.Value)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Storage Account Allows Shared Key Access",
                            Description = $"Storage account '{data.Name}' allows shared key (storage account key) access. Azure AD authentication is more secure.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.DataProtection,
                            ResourceId = storageAccount.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Storage/storageAccounts",
                            Recommendation = "Consider disabling shared key access and using Azure AD authentication with managed identities for better security and auditing.",
                            CanAutoRemediate = false,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check if blob soft delete is enabled
                    try
                    {
                        var blobServices = storageAccount.GetBlobService();
                        if (blobServices != null)
                        {
                            var blobService = await blobServices.GetAsync(cancellationToken);
                            var deleteRetentionPolicy = blobService.Value.Data.DeleteRetentionPolicy;

                            if (deleteRetentionPolicy == null || !deleteRetentionPolicy.IsEnabled.GetValueOrDefault())
                            {
                                findings.Add(new SecurityFinding
                                {
                                    Title = "Blob Soft Delete Not Enabled",
                                    Description = $"Storage account '{data.Name}' does not have soft delete enabled for blobs. Deleted data cannot be recovered.",
                                    Severity = Severity.Medium,
                                    Category = FindingCategory.DataProtection,
                                    ResourceId = storageAccount.Id.ToString(),
                                    ResourceName = data.Name,
                                    ResourceType = "Microsoft.Storage/storageAccounts",
                                    Recommendation = "Enable soft delete for blobs with appropriate retention period (recommended: 7-365 days) to protect against accidental deletion.",
                                    CanAutoRemediate = true,
                                    RemediationAction = "Enable blob soft delete with 7-day retention",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["ResourceGroup"] = resourceGroup.Data.Name
                                    }
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to check blob soft delete for storage account {AccountName}", data.Name);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check storage account security");
        }
    }

    private async Task CheckKeyVaultSecurity(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var keyVaults = resourceGroup.GetVaults();

                await foreach (var keyVault in keyVaults.GetAllAsync(cancellationToken: cancellationToken))
                {
                    var data = keyVault.Data;

                    // Check if soft delete is enabled
                    if (!data.Properties.EnableSoftDelete.HasValue || !data.Properties.EnableSoftDelete.Value)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Key Vault Soft Delete Not Enabled",
                            Description = $"Key Vault '{data.Name}' does not have soft delete enabled. Deleted vaults and secrets cannot be recovered.",
                            Severity = Severity.High,
                            Category = FindingCategory.DataProtection,
                            ResourceId = keyVault.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.KeyVault/vaults",
                            Recommendation = "Enable soft delete to protect against accidental or malicious deletion of Key Vault and its contents.",
                            CanAutoRemediate = true,
                            RemediationAction = "Enable soft delete on Key Vault",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check if purge protection is enabled
                    if (!data.Properties.EnablePurgeProtection.HasValue || !data.Properties.EnablePurgeProtection.Value)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Key Vault Purge Protection Not Enabled",
                            Description = $"Key Vault '{data.Name}' does not have purge protection enabled. Soft-deleted vaults can be permanently purged.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.DataProtection,
                            ResourceId = keyVault.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.KeyVault/vaults",
                            Recommendation = "Enable purge protection to prevent permanent deletion during the soft delete retention period. This is especially important for production vaults.",
                            CanAutoRemediate = true,
                            RemediationAction = "Enable purge protection on Key Vault",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check for network restrictions
                    var networkAcls = data.Properties.NetworkAcls;
                    if (networkAcls == null || networkAcls.DefaultAction.ToString() == "Allow")
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "Key Vault Has No Network Restrictions",
                            Description = $"Key Vault '{data.Name}' allows access from all networks. This increases the attack surface.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.DataProtection,
                            ResourceId = keyVault.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.KeyVault/vaults",
                            Recommendation = "Configure network rules to restrict access to Key Vault from specific virtual networks or IP addresses. Enable private endpoints for maximum security.",
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
            _logger.LogWarning(ex, "Failed to check Key Vault security");
        }
    }
}
