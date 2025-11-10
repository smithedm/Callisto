# Azure Authentication Setup Guide

This guide will help you connect Callisto to your Azure subscription.

## Method 1: Azure CLI (Easiest for Local Development)

### Prerequisites
- Azure CLI installed on your machine
- An Azure account with access to the subscription you want to scan

### Steps

1. **Install Azure CLI** (if not already installed)
   - **macOS**: `brew install azure-cli`
   - **Windows**: Download from https://aka.ms/installazurecliwindows
   - **Linux**: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`

2. **Login to Azure**
   ```bash
   az login
   ```
   This will open a browser window for authentication.

3. **Set your subscription**
   ```bash
   # List available subscriptions
   az account list --output table

   # Set the subscription you want to use
   az account set --subscription "YOUR_SUBSCRIPTION_ID"

   # Verify
   az account show
   ```

4. **Test the connection**
   ```bash
   cd src/Callisto
   dotnet run -- scan --subscription YOUR_SUBSCRIPTION_ID
   ```

## Method 2: Service Principal (For Automation/CI/CD)

### Create a Service Principal

1. **Login to Azure CLI**
   ```bash
   az login
   ```

2. **Create a Service Principal with Reader role** (for scanning only)
   ```bash
   az ad sp create-for-rbac \
     --name "CallistoScanner" \
     --role "Reader" \
     --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID"
   ```

   This will output:
   ```json
   {
     "appId": "00000000-0000-0000-0000-000000000000",
     "displayName": "CallistoScanner",
     "password": "your-secret-here",
     "tenant": "00000000-0000-0000-0000-000000000000"
   }
   ```

3. **Create a Service Principal with Contributor role** (for scanning AND remediation)
   ```bash
   az ad sp create-for-rbac \
     --name "CallistoRemediator" \
     --role "Contributor" \
     --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID"
   ```

### Configure Environment Variables

1. **Create .env file** (copy from .env.example)
   ```bash
   cp .env.example .env
   ```

2. **Edit .env with your credentials**
   ```bash
   AZURE_SUBSCRIPTION_ID=your-subscription-id
   AZURE_TENANT_ID=your-tenant-id-from-sp-output
   AZURE_CLIENT_ID=appId-from-sp-output
   AZURE_CLIENT_SECRET=password-from-sp-output
   ```

3. **Load environment variables before running**
   ```bash
   # Linux/macOS
   export $(cat .env | xargs)

   # Windows PowerShell
   Get-Content .env | ForEach-Object {
     if ($_ -match '^([^=]+)=(.+)$') {
       [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
     }
   }
   ```

4. **Run Callisto**
   ```bash
   cd src/Callisto
   dotnet run -- scan --subscription $AZURE_SUBSCRIPTION_ID
   ```

## Method 3: Azure Managed Identity (For Azure-hosted Applications)

If you're running Callisto on an Azure VM, App Service, or Container Instance:

1. **Enable System-assigned Managed Identity** on your Azure resource
   ```bash
   # For VM
   az vm identity assign --name MyVM --resource-group MyResourceGroup

   # For App Service
   az webapp identity assign --name MyAppService --resource-group MyResourceGroup
   ```

2. **Assign permissions to the Managed Identity**
   ```bash
   # Get the principal ID
   PRINCIPAL_ID=$(az vm show --name MyVM --resource-group MyResourceGroup --query identity.principalId -o tsv)

   # Assign Reader role for scanning
   az role assignment create \
     --assignee $PRINCIPAL_ID \
     --role "Reader" \
     --scope "/subscriptions/YOUR_SUBSCRIPTION_ID"

   # Or Contributor for remediation
   az role assignment create \
     --assignee $PRINCIPAL_ID \
     --role "Contributor" \
     --scope "/subscriptions/YOUR_SUBSCRIPTION_ID"
   ```

3. **Run Callisto** - it will automatically use the Managed Identity

## Required Azure Permissions

### For Scanning (Read-Only)
- **Reader** role on the subscription or specific resource groups

### For Remediation (Making Changes)
Minimum required permissions:
- **Contributor** role on the subscription (most remediations)
- **Security Admin** role (for Microsoft Defender settings)
- **User Access Administrator** (for IAM-related remediations)

### Custom Role (Least Privilege)
Create a custom role with specific permissions:

```bash
az role definition create --role-definition '{
  "Name": "Callisto Security Remediator",
  "Description": "Custom role for Callisto security remediation",
  "Actions": [
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.Sql/servers/write",
    "Microsoft.Sql/servers/databases/write",
    "Microsoft.Sql/servers/firewallRules/delete",
    "Microsoft.Web/sites/write",
    "Microsoft.Network/publicIPAddresses/delete",
    "Microsoft.Security/pricings/write",
    "Microsoft.Authorization/locks/write"
  ],
  "AssignableScopes": ["/subscriptions/YOUR_SUBSCRIPTION_ID"]
}'
```

## Verifying Your Connection

Test your authentication setup:

```bash
cd src/Callisto

# Quick test - scan with verbose output
dotnet run -- scan \
  --subscription YOUR_SUBSCRIPTION_ID \
  --categories iam \
  --verbose
```

If successful, you should see:
```
Successfully authenticated to Azure
Scanning subscription: Your Subscription Name
```

## Troubleshooting

### "No valid Azure credentials found"
- Ensure you've logged in with `az login` OR
- Set environment variables for service principal OR
- Enabled Managed Identity if running on Azure

### "Insufficient permissions"
- For scanning: Ensure you have Reader role
- For remediation: Ensure you have Contributor role
- Check role assignments: `az role assignment list --assignee YOUR_EMAIL`

### "Subscription not found"
- Verify subscription ID: `az account list --output table`
- Ensure you have access: `az account show --subscription YOUR_SUBSCRIPTION_ID`

### "Token expired"
- Re-login: `az login`
- For service principal: Verify credentials in .env are correct

## Next Steps

Once authenticated, try these commands:

```bash
# Generate a full security report
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -o html -p security-report.html

# Scan specific security areas
dotnet run -- scan -s YOUR_SUBSCRIPTION_ID -c data network

# Fix critical issues (interactive)
dotnet run -- fix -s YOUR_SUBSCRIPTION_ID
```

## Security Best Practices

1. **Never commit credentials to git** - .env is in .gitignore
2. **Use Managed Identity** when running on Azure
3. **Use least privilege** - Reader for scanning, Contributor only when fixing
4. **Rotate service principal secrets** regularly
5. **Use separate service principals** for dev/test/prod
6. **Enable MFA** on accounts with elevated permissions

## Getting Your Subscription ID

```bash
# List all subscriptions
az account list --query "[].{Name:name, ID:id}" --output table

# Show current subscription
az account show --query "{Name:name, ID:id}" --output table

# Or from Azure Portal
# Portal → Subscriptions → Click your subscription → Copy Subscription ID
```
