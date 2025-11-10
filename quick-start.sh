#!/bin/bash

# Callisto Quick Start Script
# This script helps you get started with Callisto

set -e

echo "🛡️  Callisto - Azure Security Scanner"
echo "===================================="
echo ""

# Check if .NET is installed
if ! command -v dotnet &> /dev/null; then
    echo "❌ .NET SDK not found!"
    echo "Please install .NET 8.0 SDK from: https://dotnet.microsoft.com/download"
    exit 1
fi

echo "✅ .NET SDK found: $(dotnet --version)"
echo ""

# Check if Azure CLI is installed
if command -v az &> /dev/null; then
    echo "✅ Azure CLI found: $(az version --query '\"azure-cli\"' -o tsv 2>/dev/null || echo 'installed')"

    # Check if logged in
    if az account show &> /dev/null; then
        SUBSCRIPTION_ID=$(az account show --query id -o tsv)
        SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
        echo "✅ Authenticated to Azure"
        echo "   Subscription: $SUBSCRIPTION_NAME"
        echo "   ID: $SUBSCRIPTION_ID"
        echo ""

        # Offer to scan
        read -p "Do you want to run a quick security scan? (y/n) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Starting security scan..."
            echo ""
            cd src/Callisto
            dotnet run -- scan --subscription "$SUBSCRIPTION_ID" --categories iam --min-severity high
        fi
    else
        echo "⚠️  Not authenticated to Azure"
        echo "   Run: az login"
        exit 1
    fi
else
    echo "⚠️  Azure CLI not found"
    echo ""
    echo "Choose an authentication method:"
    echo "1. Install Azure CLI (recommended): https://docs.microsoft.com/cli/azure/install-azure-cli"
    echo "2. Use Service Principal (see SETUP_AZURE_AUTH.md)"
    echo ""

    # Check for environment variables
    if [ -n "$AZURE_CLIENT_ID" ] && [ -n "$AZURE_CLIENT_SECRET" ] && [ -n "$AZURE_TENANT_ID" ]; then
        echo "✅ Service Principal credentials found in environment"

        if [ -n "$AZURE_SUBSCRIPTION_ID" ]; then
            echo "✅ Subscription ID found: $AZURE_SUBSCRIPTION_ID"
            echo ""
            read -p "Do you want to run a quick security scan? (y/n) " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "Starting security scan..."
                echo ""
                cd src/Callisto
                dotnet run -- scan --subscription "$AZURE_SUBSCRIPTION_ID" --categories iam --min-severity high
            fi
        else
            echo "⚠️  AZURE_SUBSCRIPTION_ID not set"
            echo "   Set it with: export AZURE_SUBSCRIPTION_ID=your-subscription-id"
            exit 1
        fi
    else
        echo "❌ No authentication method configured"
        echo ""
        echo "See SETUP_AZURE_AUTH.md for setup instructions"
        exit 1
    fi
fi

echo ""
echo "📖 Next steps:"
echo "   - Full scan: dotnet run -- scan --subscription YOUR_SUBSCRIPTION_ID"
echo "   - HTML report: dotnet run -- scan -s YOUR_SUB_ID -o html -p report.html"
echo "   - Fix issues: dotnet run -- fix --subscription YOUR_SUBSCRIPTION_ID"
echo ""
echo "📚 Documentation: README.md and SETUP_AZURE_AUTH.md"
