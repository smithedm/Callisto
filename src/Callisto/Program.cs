using System.CommandLine;
using Callisto.Models;
using Callisto.Scanners;
using Callisto.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace Callisto;

class Program
{
    static async Task<int> Main(string[] args)
    {
        // Create root command
        var rootCommand = new RootCommand("Callisto - Azure Security Scanner and Remediation Tool");

        // Scan command
        var scanCommand = new Command("scan", "Scan Azure subscription for security issues");

        var subscriptionOption = new Option<string>(
            name: "--subscription",
            description: "Azure subscription ID to scan")
        {
            IsRequired = true
        };
        subscriptionOption.AddAlias("-s");

        var outputFormatOption = new Option<string>(
            name: "--output-format",
            description: "Output format: console, json, html, csv",
            getDefaultValue: () => "console");
        outputFormatOption.AddAlias("-o");

        var outputPathOption = new Option<string?>(
            name: "--output-path",
            description: "Path to save the report (required for json, html, csv)");
        outputPathOption.AddAlias("-p");

        var verboseOption = new Option<bool>(
            name: "--verbose",
            description: "Enable verbose logging",
            getDefaultValue: () => false);
        verboseOption.AddAlias("-v");

        var categoriesOption = new Option<string[]>(
            name: "--categories",
            description: "Specific categories to scan: iam, network, data, monitoring, compliance, resource (default: all)")
        {
            AllowMultipleArgumentsPerToken = true
        };
        categoriesOption.AddAlias("-c");

        var minimumSeverityOption = new Option<string>(
            name: "--min-severity",
            description: "Minimum severity to report: critical, high, medium, low, info",
            getDefaultValue: () => "info");
        minimumSeverityOption.AddAlias("-m");

        scanCommand.AddOption(subscriptionOption);
        scanCommand.AddOption(outputFormatOption);
        scanCommand.AddOption(outputPathOption);
        scanCommand.AddOption(verboseOption);
        scanCommand.AddOption(categoriesOption);
        scanCommand.AddOption(minimumSeverityOption);

        scanCommand.SetHandler(async (subscriptionId, outputFormat, outputPath, verbose, categories, minSeverity) =>
        {
            await ExecuteScanAsync(subscriptionId, outputFormat, outputPath, verbose, categories, minSeverity);
        }, subscriptionOption, outputFormatOption, outputPathOption, verboseOption, categoriesOption, minimumSeverityOption);

        rootCommand.AddCommand(scanCommand);

        // Fix command
        var fixCommand = new Command("fix", "Remediate security findings");

        var fixSubscriptionOption = new Option<string>(
            name: "--subscription",
            description: "Azure subscription ID")
        {
            IsRequired = true
        };
        fixSubscriptionOption.AddAlias("-s");

        var autoApproveOption = new Option<bool>(
            name: "--auto-approve",
            description: "Automatically approve all remediations without confirmation",
            getDefaultValue: () => false);
        autoApproveOption.AddAlias("-y");

        var fixCategoriesOption = new Option<string[]>(
            name: "--categories",
            description: "Specific categories to remediate: iam, network, data, monitoring, compliance, resource (default: all)")
        {
            AllowMultipleArgumentsPerToken = true
        };
        fixCategoriesOption.AddAlias("-c");

        fixCommand.AddOption(fixSubscriptionOption);
        fixCommand.AddOption(autoApproveOption);
        fixCommand.AddOption(verboseOption);
        fixCommand.AddOption(fixCategoriesOption);

        fixCommand.SetHandler(async (subscriptionId, autoApprove, verbose, categories) =>
        {
            await ExecuteFixAsync(subscriptionId, autoApprove, verbose, categories);
        }, fixSubscriptionOption, autoApproveOption, verboseOption, fixCategoriesOption);

        rootCommand.AddCommand(fixCommand);

        // Show banner
        ShowBanner();

        return await rootCommand.InvokeAsync(args);
    }

    static void ShowBanner()
    {
        var banner = new FigletText("Callisto")
            .Centered()
            .Color(Color.Blue);

        AnsiConsole.Write(banner);
        AnsiConsole.MarkupLine("[grey]Azure Security Scanner & Remediation Tool[/]");
        AnsiConsole.MarkupLine("[grey]Version 1.0.0[/]");
        AnsiConsole.WriteLine();
    }

    static async Task ExecuteScanAsync(
        string subscriptionId,
        string outputFormat,
        string? outputPath,
        bool verbose,
        string[] categories,
        string minSeverity)
    {
        try
        {
            var services = BuildServiceProvider(verbose);

            var config = new CallistoConfiguration
            {
                SubscriptionId = subscriptionId,
                VerboseLogging = verbose,
                OutputFormat = ParseOutputFormat(outputFormat),
                OutputPath = outputPath,
                ScanOptions = BuildScanOptions(categories, minSeverity)
            };

            // Validate output path for non-console formats
            if (config.OutputFormat != OutputFormat.Console && string.IsNullOrEmpty(outputPath))
            {
                AnsiConsole.MarkupLine("[red]Error: --output-path is required for {0} format[/]", outputFormat);
                return;
            }

            var scannerService = services.GetRequiredService<SecurityScannerService>();
            var reportGenerator = services.GetRequiredService<ReportGenerator>();

            var result = await scannerService.ScanSubscriptionAsync(subscriptionId, config);

            // Generate report
            switch (config.OutputFormat)
            {
                case OutputFormat.Console:
                    reportGenerator.GenerateConsoleReport(result);
                    break;

                case OutputFormat.Json:
                    await reportGenerator.GenerateJsonReport(result, outputPath!);
                    AnsiConsole.MarkupLine($"[green]Report saved to:[/] {outputPath}");
                    break;

                case OutputFormat.Html:
                    await reportGenerator.GenerateHtmlReport(result, outputPath!);
                    AnsiConsole.MarkupLine($"[green]Report saved to:[/] {outputPath}");
                    break;

                case OutputFormat.Csv:
                    await reportGenerator.GenerateCsvReport(result, outputPath!);
                    AnsiConsole.MarkupLine($"[green]Report saved to:[/] {outputPath}");
                    break;
            }

            if (result.TotalFindings > 0)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine($"[yellow]Run 'callisto fix --subscription {subscriptionId}' to remediate auto-fixable issues[/]");
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            Environment.Exit(1);
        }
    }

    static async Task ExecuteFixAsync(
        string subscriptionId,
        bool autoApprove,
        bool verbose,
        string[] categories)
    {
        try
        {
            var services = BuildServiceProvider(verbose);

            var config = new CallistoConfiguration
            {
                SubscriptionId = subscriptionId,
                VerboseLogging = verbose,
                ScanOptions = BuildScanOptions(categories, "info")
            };

            AnsiConsole.MarkupLine("[bold]Step 1: Scanning for issues...[/]");
            AnsiConsole.WriteLine();

            var scannerService = services.GetRequiredService<SecurityScannerService>();
            var result = await scannerService.ScanSubscriptionAsync(subscriptionId, config);

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Step 2: Remediating findings...[/]");

            var remediationService = services.GetRequiredService<RemediationService>();
            var remediationResults = await remediationService.RemediateFindingsAsync(result.Findings, autoApprove);

            // Summary
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold green]Remediation Summary[/]").RuleStyle("green"));
            AnsiConsole.WriteLine();

            var successCount = remediationResults.Count(r => r.Success);
            var failureCount = remediationResults.Count(r => !r.Success);

            AnsiConsole.MarkupLine($"[green]✓ Successful:[/] {successCount}");
            AnsiConsole.MarkupLine($"[red]✗ Failed:[/] {failureCount}");
            AnsiConsole.WriteLine();

            if (failureCount > 0)
            {
                AnsiConsole.MarkupLine("[yellow]Some remediations failed. Check the output above for details.[/]");
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            Environment.Exit(1);
        }
    }

    static ServiceProvider BuildServiceProvider(bool verbose)
    {
        var services = new ServiceCollection();

        // Logging
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Warning);
        });

        // Services
        services.AddSingleton<AzureAuthenticationService>();
        services.AddSingleton<RemediationService>();
        services.AddSingleton<ReportGenerator>();
        services.AddSingleton<SecurityScannerService>();

        // Scanners
        services.AddSingleton<ISecurityScanner, IamSecurityScanner>();
        services.AddSingleton<ISecurityScanner, NetworkSecurityScanner>();
        services.AddSingleton<ISecurityScanner, DataProtectionScanner>();
        services.AddSingleton<ISecurityScanner, MonitoringSecurityScanner>();
        services.AddSingleton<ISecurityScanner, ComplianceScanner>();
        services.AddSingleton<ISecurityScanner, ResourceSecurityScanner>();

        return services.BuildServiceProvider();
    }

    static OutputFormat ParseOutputFormat(string format)
    {
        return format.ToLower() switch
        {
            "json" => OutputFormat.Json,
            "html" => OutputFormat.Html,
            "csv" => OutputFormat.Csv,
            _ => OutputFormat.Console
        };
    }

    static ScanOptions BuildScanOptions(string[] categories, string minSeverity)
    {
        var options = new ScanOptions();

        if (categories.Any())
        {
            // Disable all, then enable only requested
            options.EnableIamScanner = false;
            options.EnableNetworkScanner = false;
            options.EnableDataProtectionScanner = false;
            options.EnableMonitoringScanner = false;
            options.EnableComplianceScanner = false;
            options.EnableResourceScanner = false;

            foreach (var category in categories)
            {
                switch (category.ToLower())
                {
                    case "iam":
                        options.EnableIamScanner = true;
                        break;
                    case "network":
                        options.EnableNetworkScanner = true;
                        break;
                    case "data":
                        options.EnableDataProtectionScanner = true;
                        break;
                    case "monitoring":
                        options.EnableMonitoringScanner = true;
                        break;
                    case "compliance":
                        options.EnableComplianceScanner = true;
                        break;
                    case "resource":
                        options.EnableResourceScanner = true;
                        break;
                }
            }
        }

        // Set minimum severity filter
        var minSev = minSeverity.ToLower() switch
        {
            "critical" => Severity.Critical,
            "high" => Severity.High,
            "medium" => Severity.Medium,
            "low" => Severity.Low,
            _ => Severity.Info
        };

        options.MinimumSeverity = new List<Severity>();
        foreach (Severity sev in Enum.GetValues(typeof(Severity)))
        {
            if (sev >= minSev)
            {
                options.MinimumSeverity.Add(sev);
            }
        }

        return options;
    }
}
