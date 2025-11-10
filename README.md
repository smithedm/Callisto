# Callisto

**Callisto** is a comprehensive Azure security scanning and remediation tool that helps you secure your Azure subscriptions by identifying security misconfigurations and automatically fixing them.

## Features

### Security Scanning Categories

Callisto scans your Azure subscription across **6 major security categories**:

#### 1. **Identity & Access Management (IAM)**
- Owner role assignment detection
- Custom roles with wildcard permissions
- Overly permissive custom roles
- Dangerous permission detection

#### 2. **Network Security**
- Network Security Group (NSG) rules exposing critical ports to the Internet
- Unattached public IP addresses
- NSGs with no custom rules
- Overly permissive firewall rules

#### 3. **Data Protection**
- Storage account security (HTTPS enforcement, TLS version, public blob access)
- Key Vault security (soft delete, purge protection, network restrictions)
- Blob soft delete configuration
- Encryption settings

#### 4. **Monitoring & Threat Detection**
- Microsoft Defender for Cloud plans status
- Critical workload protection coverage
- Security monitoring enablement

#### 5. **Compliance & Governance**
- Resource tagging compliance
- Resource locks on critical resources
- Governance policy adherence

#### 6. **Resource Security**
- Virtual Machine disk encryption
- VMs with public IP addresses
- SQL Server Azure AD authentication
- SQL Server firewall rules (overly permissive access)
- SQL Database Transparent Data Encryption (TDE)
- App Service HTTPS enforcement
- App Service TLS version
- App Service managed identity

### Auto-Remediation

Callisto can automatically fix many security issues including:

- ✅ Enabling HTTPS-only on Storage Accounts
- ✅ Updating minimum TLS version to 1.2
- ✅ Disabling public blob access on Storage Accounts
- ✅ Enabling soft delete on Storage Accounts and Key Vaults
- ✅ Enabling purge protection on Key Vaults
- ✅ Removing overly permissive SQL firewall rules
- ✅ Enabling TDE on SQL Databases
- ✅ Enabling HTTPS-only on App Services
- ✅ Enabling managed identity on App Services
- ✅ Deleting unattached public IP addresses
- ✅ Enabling Microsoft Defender for Cloud plans
- ✅ Applying resource locks to critical resources

### Report Formats

Generate security reports in multiple formats:
- **Console** - Rich, colorful terminal output with charts
- **JSON** - Machine-readable format for integration
- **HTML** - Beautiful web-based report with styling
- **CSV** - Spreadsheet-compatible format

## Prerequisites

- **.NET 8.0 SDK** or later
- **Azure CLI** (for local authentication) or configured Azure credentials
- **Azure subscription** with appropriate permissions:
  - `Reader` role (minimum for scanning)
  - `Contributor` or specific write permissions (for remediation)

## Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/Callisto.git
cd Callisto
```

### Build the Project

```bash
cd src/Callisto
dotnet build
```

### Run the Application

```bash
dotnet run -- scan --subscription YOUR_SUBSCRIPTION_ID
```

## Authentication

Callisto uses **Azure Default Credential Chain** which tries authentication methods in this order:

1. **Environment Variables** (for CI/CD)
2. **Managed Identity** (for Azure-hosted apps)
3. **Azure CLI** (for local development - recommended)
4. **Visual Studio** (for local development)
5. **Interactive Browser** (fallback)

### Recommended Setup for Local Development

```bash
# Login to Azure CLI
az login

# Set your default subscription
az account set --subscription YOUR_SUBSCRIPTION_ID

# Verify
az account show
```

### For CI/CD Pipelines

Set these environment variables:

```bash
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
```

## Usage

### Scan Command

Scan your Azure subscription for security issues:

```bash
# Basic scan (console output)
dotnet run -- scan --subscription YOUR_SUBSCRIPTION_ID

# Save as JSON report
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -o json -p report.json

# Save as HTML report
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -o html -p report.html

# Scan specific categories only
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -c iam network data

# Filter by minimum severity
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID --min-severity high

# Verbose logging
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID --verbose
```

### Fix Command

Remediate security findings automatically:

```bash
# Interactive remediation (prompts for confirmation)
dotnet run -- fix --subscription YOUR_SUBSCRIPTION_ID

# Auto-approve all fixes (use with caution!)
dotnet run -- fix -s YOUR_SUBSCRIPTION_ID --auto-approve

# Fix specific categories only
dotnet run -- fix -s YOUR_SUBSCRIPTION_ID -c data network

# Verbose logging
dotnet run -- fix -s YOUR_SUBSCRIPTION_ID --verbose
```

## Command Reference

### Scan Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--subscription` | `-s` | Azure subscription ID (required) | - |
| `--output-format` | `-o` | Output format: console, json, html, csv | console |
| `--output-path` | `-p` | Path to save report | - |
| `--categories` | `-c` | Categories to scan: iam, network, data, monitoring, compliance, resource | all |
| `--min-severity` | `-m` | Minimum severity: critical, high, medium, low, info | info |
| `--verbose` | `-v` | Enable verbose logging | false |

### Fix Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--subscription` | `-s` | Azure subscription ID (required) | - |
| `--auto-approve` | `-y` | Auto-approve all fixes without confirmation | false |
| `--categories` | `-c` | Categories to fix: iam, network, data, monitoring, compliance, resource | all |
| `--verbose` | `-v` | Enable verbose logging | false |

## Example Workflows

### 1. Initial Security Assessment

```bash
# Scan and generate HTML report
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -o html -p security-report.html

# Open the report in your browser
open security-report.html  # macOS
# or
start security-report.html  # Windows
```

### 2. Fix Critical Issues Only

```bash
# Scan for critical issues
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID --min-severity critical

# Review and fix critical issues
dotnet run -- fix -s YOUR_SUBSCRIPTION_ID
```

### 3. Data Protection Focus

```bash
# Scan only data protection
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -c data

# Fix data protection issues
dotnet run -- fix -s YOUR_SUBSCRIPTION_ID -c data
```

### 4. Compliance Reporting

```bash
# Generate CSV for compliance team
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -o csv -p compliance-report.csv

# Generate JSON for security automation
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -o json -p findings.json
```

## Security Findings Reference

### Critical Severity
- NSG rules exposing database/management ports (22, 3389, 1433, 3306, 5432, etc.) to the Internet
- SQL Server firewall allowing all IP addresses (0.0.0.0-255.255.255.255)

### High Severity
- Owner role assignments
- Storage accounts not enforcing HTTPS
- Storage accounts with outdated TLS versions
- Storage accounts allowing public blob access
- Key Vault without soft delete
- App Services not enforcing HTTPS
- App Services with outdated TLS versions
- Virtual machines without disk encryption
- SQL databases without TDE

### Medium Severity
- Custom roles with wildcard permissions
- NSG rules allowing inbound traffic from any source
- Key Vault without purge protection
- Key Vault without network restrictions
- SQL Server without Azure AD authentication
- App Services without managed identity
- VMs with public IP addresses
- Critical resources without locks

### Low Severity
- NSGs with no custom rules
- Unattached public IP addresses
- Resources missing tags
- SQL Server allowing all Azure services

## Permissions Required

### For Scanning (Read-Only)

Minimum required role: **Reader** on subscription

### For Remediation

Required permissions vary by resource type. Recommended roles:
- **Contributor** (most remediations)
- **Security Admin** (Defender for Cloud)
- **User Access Administrator** (IAM changes)

Alternatively, create a custom role with specific permissions for the resources you want to remediate.

## Architecture

```
Callisto/
├── Models/                      # Data models
│   ├── SecurityFinding.cs       # Finding and scan result models
│   └── CallistoConfiguration.cs # Configuration models
├── Scanners/                    # Security scanners
│   ├── ISecurityScanner.cs      # Scanner interface
│   ├── IamSecurityScanner.cs
│   ├── NetworkSecurityScanner.cs
│   ├── DataProtectionScanner.cs
│   ├── MonitoringSecurityScanner.cs
│   ├── ComplianceScanner.cs
│   └── ResourceSecurityScanner.cs
├── Services/                    # Core services
│   ├── AzureAuthenticationService.cs
│   ├── SecurityScannerService.cs
│   ├── RemediationService.cs
│   └── ReportGenerator.cs
└── Program.cs                   # CLI entry point
```

## Extending Callisto

### Adding a New Scanner

1. Create a new scanner class implementing `ISecurityScanner`:

```csharp
public class MyCustomScanner : ISecurityScanner
{
    public string ScannerName => "My Custom Scanner";
    public FindingCategory Category => FindingCategory.ResourceSecurity;

    public async Task<List<SecurityFinding>> ScanAsync(
        string subscriptionId,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<SecurityFinding>();
        // Your scanning logic here
        return findings;
    }
}
```

2. Register it in `Program.cs`:

```csharp
services.AddSingleton<ISecurityScanner, MyCustomScanner>();
```

### Adding Remediation Logic

Add remediation logic to `RemediationService.cs` in the `RemediateFindingAsync` method for your resource type.

## Troubleshooting

### Authentication Issues

```
Error: No valid Azure credentials found
```

**Solution**: Login with Azure CLI:
```bash
az login
az account set --subscription YOUR_SUBSCRIPTION_ID
```

### Permission Errors

```
Error: Insufficient permissions to remediate this resource
```

**Solution**: Ensure your account has `Contributor` role or specific permissions for the resource.

### API Throttling

If scanning large subscriptions:
- Use `--categories` to scan specific areas
- Run scans during off-peak hours
- Consider scanning resource groups individually

## Best Practices

1. **Start with Read-Only**: Run scans first, review findings before fixing
2. **Test in Non-Production**: Test remediation in dev/test subscriptions first
3. **Review Before Auto-Approve**: Always review findings before using `--auto-approve`
4. **Regular Scans**: Schedule regular scans (daily/weekly) for continuous monitoring
5. **Track Progress**: Use JSON/CSV exports to track findings over time
6. **Least Privilege**: Only grant permissions needed for specific operations

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section

## Acknowledgments

Built with:
- Azure SDK for .NET
- System.CommandLine
- Spectre.Console

## Disclaimer

⚠️ **Important**: Always test in non-production environments first. Auto-remediation makes changes to your Azure resources. Review all findings and understand the impact before applying fixes.

---

**Callisto** - Secure your Azure environment with confidence! 🛡️