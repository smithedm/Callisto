# Callisto Quick Start Script for Windows PowerShell
# This script helps you get started with Callisto

Write-Host "🛡️  Callisto - Azure Security Scanner" -ForegroundColor Blue
Write-Host "====================================" -ForegroundColor Blue
Write-Host ""

# Check if .NET is installed
try {
    $dotnetVersion = dotnet --version
    Write-Host "✅ .NET SDK found: $dotnetVersion" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "❌ .NET SDK not found!" -ForegroundColor Red
    Write-Host "Please install .NET 8.0 SDK from: https://dotnet.microsoft.com/download"
    exit 1
}

# Check if Azure CLI is installed
try {
    $azVersion = az version --query '"azure-cli"' -o tsv 2>$null
    if ($azVersion) {
        Write-Host "✅ Azure CLI found: $azVersion" -ForegroundColor Green

        # Check if logged in
        try {
            $account = az account show 2>$null | ConvertFrom-Json
            $subscriptionId = $account.id
            $subscriptionName = $account.name

            Write-Host "✅ Authenticated to Azure" -ForegroundColor Green
            Write-Host "   Subscription: $subscriptionName" -ForegroundColor Gray
            Write-Host "   ID: $subscriptionId" -ForegroundColor Gray
            Write-Host ""

            # Offer to scan
            $response = Read-Host "Do you want to run a quick security scan? (y/n)"
            if ($response -eq "y" -or $response -eq "Y") {
                Write-Host "Starting security scan..." -ForegroundColor Cyan
                Write-Host ""
                Set-Location src/Callisto
                dotnet run -- scan --subscription "$subscriptionId" --categories iam --min-severity high
            }
        } catch {
            Write-Host "⚠️  Not authenticated to Azure" -ForegroundColor Yellow
            Write-Host "   Run: az login"
            exit 1
        }
    }
} catch {
    Write-Host "⚠️  Azure CLI not found" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Choose an authentication method:"
    Write-Host "1. Install Azure CLI (recommended): https://aka.ms/installazurecliwindows"
    Write-Host "2. Use Service Principal (see SETUP_AZURE_AUTH.md)"
    Write-Host ""

    # Check for environment variables
    if ($env:AZURE_CLIENT_ID -and $env:AZURE_CLIENT_SECRET -and $env:AZURE_TENANT_ID) {
        Write-Host "✅ Service Principal credentials found in environment" -ForegroundColor Green

        if ($env:AZURE_SUBSCRIPTION_ID) {
            Write-Host "✅ Subscription ID found: $env:AZURE_SUBSCRIPTION_ID" -ForegroundColor Green
            Write-Host ""
            $response = Read-Host "Do you want to run a quick security scan? (y/n)"
            if ($response -eq "y" -or $response -eq "Y") {
                Write-Host "Starting security scan..." -ForegroundColor Cyan
                Write-Host ""
                Set-Location src/Callisto
                dotnet run -- scan --subscription "$env:AZURE_SUBSCRIPTION_ID" --categories iam --min-severity high
            }
        } else {
            Write-Host "⚠️  AZURE_SUBSCRIPTION_ID not set" -ForegroundColor Yellow
            Write-Host "   Set it with: `$env:AZURE_SUBSCRIPTION_ID='your-subscription-id'"
            exit 1
        }
    } else {
        Write-Host "❌ No authentication method configured" -ForegroundColor Red
        Write-Host ""
        Write-Host "See SETUP_AZURE_AUTH.md for setup instructions"
        exit 1
    }
}

Write-Host ""
Write-Host "📖 Next steps:" -ForegroundColor Cyan
Write-Host "   - Full scan: dotnet run -- scan --subscription YOUR_SUBSCRIPTION_ID"
Write-Host "   - HTML report: dotnet run -- scan -s YOUR_SUB_ID -o html -p report.html"
Write-Host "   - Fix issues: dotnet run -- fix --subscription YOUR_SUBSCRIPTION_ID"
Write-Host ""
Write-Host "📚 Documentation: README.md and SETUP_AZURE_AUTH.md"
