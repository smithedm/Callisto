using System.Text;
using System.Text.Json;
using Callisto.Models;
using Spectre.Console;

namespace Callisto.Services;

public class ReportGenerator
{
    public void GenerateConsoleReport(ScanResult result)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold blue]Scan Summary[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        var summaryTable = new Table();
        summaryTable.Border = TableBorder.Rounded;
        summaryTable.AddColumn("Metric");
        summaryTable.AddColumn("Value");

        summaryTable.AddRow("Subscription", result.SubscriptionName);
        summaryTable.AddRow("Scan Duration", $"{(result.ScanEndTime - result.ScanStartTime).TotalSeconds:F1}s");
        summaryTable.AddRow("Total Findings", result.TotalFindings.ToString());
        summaryTable.AddRow("Remediable Findings", result.RemediableFindings.ToString());

        AnsiConsole.Write(summaryTable);
        AnsiConsole.WriteLine();

        // Findings by severity
        if (result.FindingsBySeverity.Any())
        {
            AnsiConsole.Write(new Rule("[bold]Findings by Severity[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            var severityChart = new BarChart()
                .Width(60)
                .Label("[bold]Security Findings[/]");

            foreach (var kvp in result.FindingsBySeverity.OrderByDescending(x => x.Key))
            {
                var color = kvp.Key switch
                {
                    Severity.Critical => Color.Red,
                    Severity.High => Color.Orange1,
                    Severity.Medium => Color.Yellow,
                    Severity.Low => Color.Blue,
                    _ => Color.Grey
                };

                severityChart.AddItem(kvp.Key.ToString(), kvp.Value, color);
            }

            AnsiConsole.Write(severityChart);
            AnsiConsole.WriteLine();
        }

        // Findings by category
        if (result.FindingsByCategory.Any())
        {
            AnsiConsole.Write(new Rule("[bold]Findings by Category[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            var categoryTable = new Table();
            categoryTable.Border = TableBorder.Rounded;
            categoryTable.AddColumn("Category");
            categoryTable.AddColumn("Count");

            foreach (var kvp in result.FindingsByCategory.OrderByDescending(x => x.Value))
            {
                categoryTable.AddRow(FormatCategoryName(kvp.Key), kvp.Value.ToString());
            }

            AnsiConsole.Write(categoryTable);
            AnsiConsole.WriteLine();
        }

        // Top findings
        if (result.Findings.Any())
        {
            AnsiConsole.Write(new Rule("[bold]Critical & High Severity Findings[/]").RuleStyle("red"));
            AnsiConsole.WriteLine();

            var criticalFindings = result.Findings
                .Where(f => f.Severity == Severity.Critical || f.Severity == Severity.High)
                .OrderByDescending(f => f.Severity)
                .Take(20)
                .ToList();

            if (criticalFindings.Any())
            {
                foreach (var finding in criticalFindings)
                {
                    var severityColor = finding.Severity == Severity.Critical ? "red" : "orange1";
                    var icon = finding.CanAutoRemediate ? "🔧" : "⚠️";

                    AnsiConsole.MarkupLine($"[{severityColor}]{icon} [{finding.Severity}][/] {finding.Title}");
                    AnsiConsole.MarkupLine($"   Resource: [cyan]{finding.ResourceName}[/] ({finding.ResourceType})");
                    AnsiConsole.MarkupLine($"   [grey]{finding.Description}[/]");
                    if (finding.CanAutoRemediate)
                    {
                        AnsiConsole.MarkupLine($"   [green]Can auto-fix:[/] {finding.RemediationAction}");
                    }
                    AnsiConsole.WriteLine();
                }
            }
            else
            {
                AnsiConsole.MarkupLine("[green]No critical or high severity findings! 🎉[/]");
            }
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule().RuleStyle("blue"));
    }

    public async Task GenerateJsonReport(ScanResult result, string outputPath)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        var json = JsonSerializer.Serialize(result, options);
        await File.WriteAllTextAsync(outputPath, json);
    }

    public async Task GenerateHtmlReport(ScanResult result, string outputPath)
    {
        var html = new StringBuilder();
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html lang='en'>");
        html.AppendLine("<head>");
        html.AppendLine("    <meta charset='UTF-8'>");
        html.AppendLine("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        html.AppendLine("    <title>Callisto Security Scan Report</title>");
        html.AppendLine("    <style>");
        html.AppendLine(@"
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #ecf0f1; padding: 20px; border-radius: 6px; text-align: center; }
        .summary-card h3 { margin: 0; color: #7f8c8d; font-size: 14px; font-weight: normal; }
        .summary-card .value { font-size: 32px; font-weight: bold; color: #2c3e50; margin: 10px 0; }
        .finding { border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; background: #f8f9fa; border-radius: 4px; }
        .finding.critical { border-left-color: #e74c3c; }
        .finding.high { border-left-color: #e67e22; }
        .finding.medium { border-left-color: #f39c12; }
        .finding.low { border-left-color: #3498db; }
        .finding h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
        .badge.critical { background: #e74c3c; }
        .badge.high { background: #e67e22; }
        .badge.medium { background: #f39c12; }
        .badge.low { background: #3498db; }
        .badge.info { background: #95a5a6; }
        .metadata { font-size: 13px; color: #7f8c8d; margin-top: 10px; }
        .remediable { display: inline-block; background: #27ae60; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin-left: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
    </style>");
        html.AppendLine("</head>");
        html.AppendLine("<body>");
        html.AppendLine("    <div class='container'>");
        html.AppendLine($"        <h1>🛡️ Callisto Security Scan Report</h1>");
        html.AppendLine($"        <p><strong>Subscription:</strong> {result.SubscriptionName} ({result.SubscriptionId})</p>");
        html.AppendLine($"        <p><strong>Scan Date:</strong> {result.ScanStartTime:yyyy-MM-dd HH:mm:ss} UTC</p>");
        html.AppendLine($"        <p><strong>Duration:</strong> {(result.ScanEndTime - result.ScanStartTime).TotalSeconds:F1} seconds</p>");

        html.AppendLine("        <div class='summary'>");
        html.AppendLine("            <div class='summary-card'>");
        html.AppendLine("                <h3>Total Findings</h3>");
        html.AppendLine($"                <div class='value'>{result.TotalFindings}</div>");
        html.AppendLine("            </div>");
        html.AppendLine("            <div class='summary-card'>");
        html.AppendLine("                <h3>Remediable</h3>");
        html.AppendLine($"                <div class='value'>{result.RemediableFindings}</div>");
        html.AppendLine("            </div>");

        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            var count = result.FindingsBySeverity.GetValueOrDefault(severity, 0);
            if (count > 0)
            {
                html.AppendLine("            <div class='summary-card'>");
                html.AppendLine($"                <h3>{severity} Severity</h3>");
                html.AppendLine($"                <div class='value'>{count}</div>");
                html.AppendLine("            </div>");
            }
        }

        html.AppendLine("        </div>");

        if (result.FindingsByCategory.Any())
        {
            html.AppendLine("        <h2>Findings by Category</h2>");
            html.AppendLine("        <table>");
            html.AppendLine("            <tr><th>Category</th><th>Count</th></tr>");
            foreach (var kvp in result.FindingsByCategory.OrderByDescending(x => x.Value))
            {
                html.AppendLine($"            <tr><td>{FormatCategoryName(kvp.Key)}</td><td>{kvp.Value}</td></tr>");
            }
            html.AppendLine("        </table>");
        }

        html.AppendLine("        <h2>All Findings</h2>");

        foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
        {
            var severityClass = finding.Severity.ToString().ToLower();
            html.AppendLine($"        <div class='finding {severityClass}'>");
            html.AppendLine($"            <h3>");
            html.AppendLine($"                <span class='badge {severityClass}'>{finding.Severity}</span>");
            html.AppendLine($"                {finding.Title}");
            if (finding.CanAutoRemediate)
            {
                html.AppendLine($"                <span class='remediable'>🔧 Auto-fix available</span>");
            }
            html.AppendLine($"            </h3>");
            html.AppendLine($"            <p><strong>Resource:</strong> {finding.ResourceName} ({finding.ResourceType})</p>");
            html.AppendLine($"            <p>{finding.Description}</p>");
            html.AppendLine($"            <p><strong>Recommendation:</strong> {finding.Recommendation}</p>");
            if (finding.CanAutoRemediate && !string.IsNullOrEmpty(finding.RemediationAction))
            {
                html.AppendLine($"            <p><strong>Auto-remediation:</strong> {finding.RemediationAction}</p>");
            }
            html.AppendLine($"            <div class='metadata'>");
            html.AppendLine($"                <strong>Category:</strong> {FormatCategoryName(finding.Category)} | ");
            html.AppendLine($"                <strong>Discovered:</strong> {finding.DiscoveredAt:yyyy-MM-dd HH:mm:ss} UTC");
            html.AppendLine($"            </div>");
            html.AppendLine("        </div>");
        }

        html.AppendLine("    </div>");
        html.AppendLine("</body>");
        html.AppendLine("</html>");

        await File.WriteAllTextAsync(outputPath, html.ToString());
    }

    public async Task GenerateCsvReport(ScanResult result, string outputPath)
    {
        var csv = new StringBuilder();
        csv.AppendLine("Severity,Category,Resource Name,Resource Type,Title,Description,Recommendation,Can Auto-Remediate,Remediation Action");

        foreach (var finding in result.Findings)
        {
            csv.AppendLine($"\"{finding.Severity}\"," +
                          $"\"{FormatCategoryName(finding.Category)}\"," +
                          $"\"{EscapeCsv(finding.ResourceName)}\"," +
                          $"\"{finding.ResourceType}\"," +
                          $"\"{EscapeCsv(finding.Title)}\"," +
                          $"\"{EscapeCsv(finding.Description)}\"," +
                          $"\"{EscapeCsv(finding.Recommendation)}\"," +
                          $"\"{finding.CanAutoRemediate}\"," +
                          $"\"{EscapeCsv(finding.RemediationAction ?? "")}\"");
        }

        await File.WriteAllTextAsync(outputPath, csv.ToString());
    }

    private string FormatCategoryName(FindingCategory category)
    {
        return category switch
        {
            FindingCategory.IdentityAndAccess => "Identity & Access Management",
            FindingCategory.NetworkSecurity => "Network Security",
            FindingCategory.DataProtection => "Data Protection",
            FindingCategory.MonitoringAndThreatDetection => "Monitoring & Threat Detection",
            FindingCategory.ComplianceAndGovernance => "Compliance & Governance",
            FindingCategory.ResourceSecurity => "Resource Security",
            _ => category.ToString()
        };
    }

    private string EscapeCsv(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        return value.Replace("\"", "\"\"");
    }
}
