using Callisto.Models;

namespace Callisto.Scanners;

public interface ISecurityScanner
{
    string ScannerName { get; }
    FindingCategory Category { get; }
    Task<List<SecurityFinding>> ScanAsync(string subscriptionId, CancellationToken cancellationToken = default);
}
