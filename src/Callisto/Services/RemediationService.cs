using Azure;
using Azure.ResourceManager;
using Azure.ResourceManager.AppService;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.SecurityCenter;
using Azure.ResourceManager.SecurityCenter.Models;
using Azure.ResourceManager.Sql;
using Azure.ResourceManager.Sql.Models;
using Azure.ResourceManager.Storage;
using Azure.ResourceManager.Storage.Models;
using Callisto.Models;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace Callisto.Services;

public class RemediationService
{
    private readonly AzureAuthenticationService _authService;
    private readonly ILogger<RemediationService> _logger;

    public RemediationService(AzureAuthenticationService authService, ILogger<RemediationService> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    public async Task<List<RemediationResult>> RemediateFindingsAsync(
        List<SecurityFinding> findings,
        bool autoApprove = false,
        CancellationToken cancellationToken = default)
    {
        var results = new List<RemediationResult>();
        var remediableFindings = findings.Where(f => f.CanAutoRemediate).ToList();

        if (!remediableFindings.Any())
        {
            AnsiConsole.MarkupLine("[yellow]No auto-remediable findings to fix.[/]");
            return results;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]Found {remediableFindings.Count} findings that can be automatically remediated:[/]");
        AnsiConsole.WriteLine();

        var table = new Table();
        table.AddColumn("#");
        table.AddColumn("Severity");
        table.AddColumn("Resource");
        table.AddColumn("Issue");
        table.AddColumn("Remediation");

        for (int i = 0; i < remediableFindings.Count; i++)
        {
            var finding = remediableFindings[i];
            var severityColor = finding.Severity switch
            {
                Severity.Critical => "red",
                Severity.High => "orange1",
                Severity.Medium => "yellow",
                Severity.Low => "blue",
                _ => "grey"
            };

            table.AddRow(
                (i + 1).ToString(),
                $"[{severityColor}]{finding.Severity}[/]",
                finding.ResourceName,
                finding.Title,
                finding.RemediationAction ?? "Fix issue"
            );
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        bool proceed = autoApprove;
        if (!autoApprove)
        {
            proceed = AnsiConsole.Confirm("Do you want to proceed with remediation?", false);
        }

        if (!proceed)
        {
            AnsiConsole.MarkupLine("[yellow]Remediation cancelled by user.[/]");
            return results;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold green]Starting remediation...[/]");
        AnsiConsole.WriteLine();

        var armClient = await _authService.GetArmClientAsync();

        foreach (var finding in remediableFindings)
        {
            AnsiConsole.MarkupLine($"[blue]Remediating:[/] {finding.Title} on {finding.ResourceName}...");

            try
            {
                var result = await RemediateFindingAsync(armClient, finding, cancellationToken);
                results.Add(result);

                if (result.Success)
                {
                    AnsiConsole.MarkupLine($"  [green]✓[/] {result.Message}");
                }
                else
                {
                    AnsiConsole.MarkupLine($"  [red]✗[/] {result.Message}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error remediating finding {FindingId}", finding.Id);
                results.Add(new RemediationResult
                {
                    FindingId = finding.Id,
                    Success = false,
                    Message = $"Error: {ex.Message}",
                    Error = ex.ToString()
                });
                AnsiConsole.MarkupLine($"  [red]✗[/] Error: {ex.Message}");
            }
        }

        return results;
    }

    private async Task<RemediationResult> RemediateFindingAsync(
        ArmClient armClient,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var resourceId = new Azure.Core.ResourceIdentifier(finding.ResourceId);

        try
        {
            switch (finding.ResourceType)
            {
                case "Microsoft.Storage/storageAccounts":
                    return await RemediateStorageAccountAsync(armClient, resourceId, finding, cancellationToken);

                case "Microsoft.KeyVault/vaults":
                    return await RemediateKeyVaultAsync(armClient, resourceId, finding, cancellationToken);

                case "Microsoft.Sql/servers":
                    return await RemediateSqlServerAsync(armClient, resourceId, finding, cancellationToken);

                case "Microsoft.Sql/servers/databases":
                    return await RemediateSqlDatabaseAsync(armClient, resourceId, finding, cancellationToken);

                case "Microsoft.Web/sites":
                    return await RemediateWebAppAsync(armClient, resourceId, finding, cancellationToken);

                case "Microsoft.Network/publicIPAddresses":
                    return await RemediatePublicIpAsync(armClient, resourceId, finding, cancellationToken);

                case "Microsoft.Security/pricings":
                    return await RemediateDefenderAsync(armClient, resourceId, finding, cancellationToken);

                default:
                    return await RemediateGenericResourceAsync(armClient, resourceId, finding, cancellationToken);
            }
        }
        catch (RequestFailedException ex) when (ex.Status == 403)
        {
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = false,
                Message = "Insufficient permissions to remediate this resource",
                Error = ex.Message
            };
        }
    }

    private async Task<RemediationResult> RemediateStorageAccountAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var storageAccount = armClient.GetStorageAccountResource(resourceId);
        var data = (await storageAccount.GetAsync(cancellationToken)).Value.Data;

        if (finding.Title.Contains("HTTP Traffic"))
        {
            data.EnableHttpsTrafficOnly = true;
            await storageAccount.UpdateAsync(WaitUntil.Completed, data, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled HTTPS-only traffic"
            };
        }
        else if (finding.Title.Contains("TLS Version"))
        {
            data.MinimumTlsVersion = StorageMinimumTlsVersion.Tls1_2;
            await storageAccount.UpdateAsync(WaitUntil.Completed, data, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Updated minimum TLS version to 1.2"
            };
        }
        else if (finding.Title.Contains("Public Blob Access"))
        {
            data.AllowBlobPublicAccess = false;
            await storageAccount.UpdateAsync(WaitUntil.Completed, data, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Disabled public blob access"
            };
        }
        else if (finding.Title.Contains("Soft Delete"))
        {
            var blobServices = storageAccount.GetBlobService();
            var blobService = await blobServices.GetAsync(cancellationToken);
            var blobData = blobService.Value.Data;

            blobData.DeleteRetentionPolicy = new DeleteRetentionPolicy
            {
                IsEnabled = true,
                Days = 7
            };

            await blobServices.CreateOrUpdateAsync(WaitUntil.Completed, blobData, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled soft delete with 7-day retention"
            };
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Unknown storage account issue type"
        };
    }

    private async Task<RemediationResult> RemediateKeyVaultAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var keyVault = armClient.GetVaultResource(resourceId);
        var data = (await keyVault.GetAsync(cancellationToken)).Value.Data;

        if (finding.Title.Contains("Soft Delete"))
        {
            data.Properties.EnableSoftDelete = true;
            await keyVault.UpdateAsync(WaitUntil.Completed, new VaultPatchParameters { Properties = data.Properties }, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled soft delete"
            };
        }
        else if (finding.Title.Contains("Purge Protection"))
        {
            data.Properties.EnablePurgeProtection = true;
            await keyVault.UpdateAsync(WaitUntil.Completed, new VaultPatchParameters { Properties = data.Properties }, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled purge protection"
            };
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Unknown Key Vault issue type"
        };
    }

    private async Task<RemediationResult> RemediateSqlServerAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var sqlServer = armClient.GetSqlServerResource(resourceId);

        if (finding.Title.Contains("Firewall Allows All"))
        {
            var ruleName = finding.Metadata.GetValueOrDefault("FirewallRuleName", "AllowAllWindowsAzureIps");
            var firewallRules = sqlServer.GetServerFirewallRules();

            try
            {
                var rule = await firewallRules.GetAsync(ruleName, cancellationToken);
                await rule.Value.DeleteAsync(WaitUntil.Completed, cancellationToken);

                return new RemediationResult
                {
                    FindingId = finding.Id,
                    Success = true,
                    Message = $"Deleted overly permissive firewall rule '{ruleName}'"
                };
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                return new RemediationResult
                {
                    FindingId = finding.Id,
                    Success = false,
                    Message = "Firewall rule not found or already deleted"
                };
            }
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Unknown SQL Server issue type"
        };
    }

    private async Task<RemediationResult> RemediateSqlDatabaseAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var database = armClient.GetSqlDatabaseResource(resourceId);

        if (finding.Title.Contains("TDE"))
        {
            var tdeConfigs = database.GetTransparentDataEncryptions();

            var tdeData = new TransparentDataEncryptionData
            {
                State = TransparentDataEncryptionState.Enabled
            };

            await tdeConfigs.CreateOrUpdateAsync(WaitUntil.Completed, TransparentDataEncryptionName.Current, tdeData, cancellationToken);

            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled Transparent Data Encryption"
            };
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Unknown SQL Database issue type"
        };
    }

    private async Task<RemediationResult> RemediateWebAppAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var webApp = armClient.GetWebSiteResource(resourceId);
        var data = (await webApp.GetAsync(cancellationToken)).Value.Data;

        if (finding.Title.Contains("HTTPS"))
        {
            data.IsHttpsOnly = true;
            await webApp.UpdateAsync(data, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled HTTPS only"
            };
        }
        else if (finding.Title.Contains("TLS"))
        {
            data.SiteConfig.MinTlsVersion = Azure.ResourceManager.AppService.Models.SupportedTlsVersion.Tls1_2;
            await webApp.UpdateAsync(data, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Updated minimum TLS version to 1.2"
            };
        }
        else if (finding.Title.Contains("Managed Identity"))
        {
            data.Identity = new Azure.ResourceManager.Models.ManagedServiceIdentity(Azure.ResourceManager.Models.ManagedServiceIdentityType.SystemAssigned);
            await webApp.UpdateAsync(data, cancellationToken);
            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Enabled system-assigned managed identity"
            };
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Unknown Web App issue type"
        };
    }

    private async Task<RemediationResult> RemediatePublicIpAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        if (finding.Title.Contains("Unattached"))
        {
            var publicIp = armClient.GetPublicIPAddressResource(resourceId);
            await publicIp.DeleteAsync(WaitUntil.Completed, cancellationToken);

            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Deleted unattached public IP address"
            };
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Unknown Public IP issue type"
        };
    }

    private async Task<RemediationResult> RemediateDefenderAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        var pricing = armClient.GetSecurityPricingResource(resourceId);
        var planName = finding.Metadata.GetValueOrDefault("PlanName", "");

        var pricingData = new SecurityPricingData
        {
            PricingTier = SecurityPricingTier.Standard
        };

        await pricing.UpdateAsync(pricingData, cancellationToken);

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = true,
            Message = $"Enabled Microsoft Defender for {planName}"
        };
    }

    private async Task<RemediationResult> RemediateGenericResourceAsync(
        ArmClient armClient,
        Azure.Core.ResourceIdentifier resourceId,
        SecurityFinding finding,
        CancellationToken cancellationToken)
    {
        if (finding.Title.Contains("Resource Lock"))
        {
            var resource = armClient.GetGenericResource(resourceId);
            var locks = resource.GetManagementLocks();

            var lockData = new Azure.ResourceManager.Resources.ManagementLockData(Azure.ResourceManager.Resources.Models.ManagementLockLevel.CanNotDelete)
            {
                Notes = "Lock applied by Callisto security scanner to prevent accidental deletion"
            };

            await locks.CreateOrUpdateAsync(WaitUntil.Completed, "CallistoProtectionLock", lockData, cancellationToken);

            return new RemediationResult
            {
                FindingId = finding.Id,
                Success = true,
                Message = "Applied CanNotDelete resource lock"
            };
        }

        return new RemediationResult
        {
            FindingId = finding.Id,
            Success = false,
            Message = "Remediation not implemented for this resource type"
        };
    }
}
