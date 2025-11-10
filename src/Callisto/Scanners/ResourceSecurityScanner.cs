using Azure.ResourceManager;
using Azure.ResourceManager.AppService;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Sql;
using Callisto.Models;
using Callisto.Services;
using Microsoft.Extensions.Logging;

namespace Callisto.Scanners;

public class ResourceSecurityScanner : ISecurityScanner
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<ResourceSecurityScanner> _logger;

    public string ScannerName => "Resource Security";
    public FindingCategory Category => FindingCategory.ResourceSecurity;

    public ResourceSecurityScanner(AzureAuthenticationService authService, ILogger<ResourceSecurityScanner> logger)
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
            await CheckVirtualMachines(subscription, findings, cancellationToken);
            await CheckSqlServers(subscription, findings, cancellationToken);
            await CheckWebApps(subscription, findings, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during resource security scan");
        }

        return findings;
    }

    private async Task CheckVirtualMachines(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var vms = resourceGroup.GetVirtualMachines();

                await foreach (var vm in vms.GetAllAsync(cancellationToken: cancellationToken))
                {
                    var data = vm.Data;

                    // Check for disk encryption
                    var osDisk = data.StorageProfile?.OsDisk;
                    if (osDisk?.EncryptionSettings?.Enabled != true &&
                        osDisk?.ManagedDisk?.SecurityProfile?.SecurityEncryptionType == null)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "VM Disk Encryption Not Enabled",
                            Description = $"Virtual machine '{data.Name}' does not have disk encryption enabled. Data at rest is not protected.",
                            Severity = Severity.High,
                            Category = FindingCategory.ResourceSecurity,
                            ResourceId = vm.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Compute/virtualMachines",
                            Recommendation = "Enable Azure Disk Encryption (ADE) to encrypt OS and data disks using BitLocker (Windows) or dm-crypt (Linux).",
                            CanAutoRemediate = false,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name,
                                ["Location"] = data.Location.ToString(),
                                ["OSType"] = data.StorageProfile?.OsDisk?.OSType.ToString() ?? "Unknown"
                            }
                        });
                    }

                    // Check if VM has public IP
                    foreach (var nicRef in data.NetworkProfile?.NetworkInterfaces ?? new List<Azure.ResourceManager.Compute.Models.VirtualMachineNetworkInterfaceReference>())
                    {
                        try
                        {
                            if (nicRef.Id == null) continue;

                            var nicResource = armClient.GetNetworkInterfaceResource(nicRef.Id);
                            var nic = await nicResource.GetAsync(cancellationToken);

                            foreach (var ipConfig in nic.Value.Data.IPConfigurations)
                            {
                                if (ipConfig.PublicIPAddress != null)
                                {
                                    findings.Add(new SecurityFinding
                                    {
                                        Title = "VM Has Public IP Address",
                                        Description = $"Virtual machine '{data.Name}' has a public IP address attached. This increases the attack surface.",
                                        Severity = Severity.Medium,
                                        Category = FindingCategory.ResourceSecurity,
                                        ResourceId = vm.Id.ToString(),
                                        ResourceName = data.Name,
                                        ResourceType = "Microsoft.Compute/virtualMachines",
                                        Recommendation = "Remove public IP and use Azure Bastion, VPN Gateway, or Azure Firewall for secure remote access.",
                                        CanAutoRemediate = false,
                                        Metadata = new Dictionary<string, string>
                                        {
                                            ["ResourceGroup"] = resourceGroup.Data.Name,
                                            ["PublicIPId"] = ipConfig.PublicIPAddress.Id?.ToString() ?? "Unknown"
                                        }
                                    });
                                    break;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "Failed to check network interface for VM {VMName}", data.Name);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check virtual machines");
        }
    }

    private async Task CheckSqlServers(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var sqlServers = resourceGroup.GetSqlServers();

                await foreach (var sqlServer in sqlServers.GetAllAsync(cancellationToken: cancellationToken))
                {
                    var data = sqlServer.Data;

                    // Check if Azure AD admin is configured
                    try
                    {
                        var azureADAdmins = sqlServer.GetServerAzureADAdministrators();
                        var adminsList = await azureADAdmins.GetAllAsync(cancellationToken: cancellationToken).ToListAsync(cancellationToken);

                        if (!adminsList.Any())
                        {
                            findings.Add(new SecurityFinding
                            {
                                Title = "SQL Server Azure AD Admin Not Configured",
                                Description = $"SQL Server '{data.Name}' does not have Azure AD authentication configured. Only SQL authentication is available.",
                                Severity = Severity.Medium,
                                Category = FindingCategory.ResourceSecurity,
                                ResourceId = sqlServer.Id.ToString(),
                                ResourceName = data.Name,
                                ResourceType = "Microsoft.Sql/servers",
                                Recommendation = "Configure Azure AD admin for SQL Server to enable centralized identity management and support for MFA.",
                                CanAutoRemediate = false,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ResourceGroup"] = resourceGroup.Data.Name
                                }
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to check Azure AD admins for SQL Server {ServerName}", data.Name);
                    }

                    // Check firewall rules for overly permissive access
                    try
                    {
                        var firewallRules = sqlServer.GetServerFirewallRules();

                        await foreach (var rule in firewallRules.GetAllAsync(cancellationToken: cancellationToken))
                        {
                            var startIp = rule.Data.StartIPAddress;
                            var endIp = rule.Data.EndIPAddress;

                            // Check for 0.0.0.0 to 255.255.255.255 (allow all)
                            if (startIp == "0.0.0.0" && endIp == "255.255.255.255")
                            {
                                findings.Add(new SecurityFinding
                                {
                                    Title = "SQL Server Firewall Allows All IP Addresses",
                                    Description = $"SQL Server '{data.Name}' has a firewall rule '{rule.Data.Name}' that allows connections from any IP address (0.0.0.0-255.255.255.255).",
                                    Severity = Severity.Critical,
                                    Category = FindingCategory.ResourceSecurity,
                                    ResourceId = sqlServer.Id.ToString(),
                                    ResourceName = data.Name,
                                    ResourceType = "Microsoft.Sql/servers",
                                    Recommendation = "CRITICAL: Remove this rule immediately. Restrict SQL Server access to specific IP addresses or use Private Endpoints for Azure-only access.",
                                    CanAutoRemediate = true,
                                    RemediationAction = $"Delete firewall rule '{rule.Data.Name}'",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["ResourceGroup"] = resourceGroup.Data.Name,
                                        ["FirewallRuleName"] = rule.Data.Name
                                    }
                                });
                            }
                            else if (startIp == "0.0.0.0" && endIp == "0.0.0.0")
                            {
                                // This is the "Allow Azure services" rule
                                findings.Add(new SecurityFinding
                                {
                                    Title = "SQL Server Allows All Azure Services",
                                    Description = $"SQL Server '{data.Name}' allows access from all Azure services. This may be broader than necessary.",
                                    Severity = Severity.Low,
                                    Category = FindingCategory.ResourceSecurity,
                                    ResourceId = sqlServer.Id.ToString(),
                                    ResourceName = data.Name,
                                    ResourceType = "Microsoft.Sql/servers",
                                    Recommendation = "Review if all Azure services need access. Consider using Private Endpoints or specific VNet rules instead.",
                                    CanAutoRemediate = false,
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
                        _logger.LogDebug(ex, "Failed to check firewall rules for SQL Server {ServerName}", data.Name);
                    }

                    // Check databases for TDE
                    try
                    {
                        var databases = sqlServer.GetSqlDatabases();

                        await foreach (var database in databases.GetAllAsync(cancellationToken: cancellationToken))
                        {
                            if (database.Data.Name == "master") continue;

                            try
                            {
                                var tdeConfigs = database.GetTransparentDataEncryptions();
                                var tdeConfig = await tdeConfigs.GetAsync("current", cancellationToken);

                                if (tdeConfig.Value.Data.State.ToString() != "Enabled")
                                {
                                    findings.Add(new SecurityFinding
                                    {
                                        Title = "SQL Database TDE Not Enabled",
                                        Description = $"Transparent Data Encryption is not enabled on database '{database.Data.Name}' in server '{data.Name}'.",
                                        Severity = Severity.High,
                                        Category = FindingCategory.ResourceSecurity,
                                        ResourceId = database.Id.ToString(),
                                        ResourceName = database.Data.Name,
                                        ResourceType = "Microsoft.Sql/servers/databases",
                                        Recommendation = "Enable Transparent Data Encryption (TDE) to protect data at rest from unauthorized access to physical media.",
                                        CanAutoRemediate = true,
                                        RemediationAction = "Enable TDE on database",
                                        Metadata = new Dictionary<string, string>
                                        {
                                            ["ServerName"] = data.Name,
                                            ["ResourceGroup"] = resourceGroup.Data.Name
                                        }
                                    });
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, "Failed to check TDE for database {DatabaseName}", database.Data.Name);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to check databases for SQL Server {ServerName}", data.Name);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check SQL servers");
        }
    }

    private async Task CheckWebApps(SubscriptionResource subscription, List<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var resourceGroup in subscription.GetResourceGroups().GetAllAsync(cancellationToken: cancellationToken))
            {
                var webApps = resourceGroup.GetWebSites();

                await foreach (var webApp in webApps.GetAllAsync(cancellationToken: cancellationToken))
                {
                    var data = webApp.Data;

                    // Check if HTTPS only is enforced
                    if (!data.IsHttpsOnly.HasValue || !data.IsHttpsOnly.Value)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "App Service Does Not Enforce HTTPS",
                            Description = $"App Service '{data.Name}' does not enforce HTTPS. Traffic can be transmitted unencrypted.",
                            Severity = Severity.High,
                            Category = FindingCategory.ResourceSecurity,
                            ResourceId = webApp.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Web/sites",
                            Recommendation = "Enable 'HTTPS Only' setting to ensure all traffic is encrypted in transit.",
                            CanAutoRemediate = true,
                            RemediationAction = "Enable HTTPS only",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check minimum TLS version
                    if (data.SiteConfig?.MinTlsVersion != null &&
                        (data.SiteConfig.MinTlsVersion.ToString() == "1.0" ||
                         data.SiteConfig.MinTlsVersion.ToString() == "1.1"))
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "App Service Uses Outdated TLS Version",
                            Description = $"App Service '{data.Name}' allows TLS 1.0 or 1.1, which have known vulnerabilities.",
                            Severity = Severity.High,
                            Category = FindingCategory.ResourceSecurity,
                            ResourceId = webApp.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Web/sites",
                            Recommendation = "Set minimum TLS version to 1.2 or higher to protect against protocol vulnerabilities.",
                            CanAutoRemediate = true,
                            RemediationAction = "Update minimum TLS version to 1.2",
                            Metadata = new Dictionary<string, string>
                            {
                                ["CurrentTlsVersion"] = data.SiteConfig.MinTlsVersion.ToString(),
                                ["ResourceGroup"] = resourceGroup.Data.Name
                            }
                        });
                    }

                    // Check if managed identity is enabled
                    if (data.Identity == null || data.Identity.ManagedServiceIdentityType.ToString() == "None")
                    {
                        findings.Add(new SecurityFinding
                        {
                            Title = "App Service Managed Identity Not Enabled",
                            Description = $"App Service '{data.Name}' does not have managed identity enabled. Using connection strings or keys may be less secure.",
                            Severity = Severity.Medium,
                            Category = FindingCategory.ResourceSecurity,
                            ResourceId = webApp.Id.ToString(),
                            ResourceName = data.Name,
                            ResourceType = "Microsoft.Web/sites",
                            Recommendation = "Enable system-assigned or user-assigned managed identity to authenticate to Azure services without storing credentials.",
                            CanAutoRemediate = true,
                            RemediationAction = "Enable system-assigned managed identity",
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
            _logger.LogWarning(ex, "Failed to check web apps");
        }
    }
}
