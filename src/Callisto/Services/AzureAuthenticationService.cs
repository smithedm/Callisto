using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Microsoft.Extensions.Logging;

namespace Callisto.Services;

public class AzureAuthenticationService
{
    private readonly ILogger<AzureAuthenticationService> _logger;
    private ArmClient? _armClient;
    private TokenCredential? _credential;

    public AzureAuthenticationService(ILogger<AzureAuthenticationService> logger)
    {
        _logger = logger;
    }

    public async Task<ArmClient> GetArmClientAsync()
    {
        if (_armClient != null)
            return _armClient;

        _credential = GetCredential();
        _armClient = new ArmClient(_credential);

        _logger.LogInformation("Successfully authenticated to Azure");
        return _armClient;
    }

    public TokenCredential GetCredential()
    {
        if (_credential != null)
            return _credential;

        // Try multiple authentication methods in order:
        // 1. Environment variables (for automation/CI/CD)
        // 2. Managed Identity (for Azure-hosted applications)
        // 3. Azure CLI (for local development)
        // 4. Visual Studio (for local development)
        // 5. Interactive browser (fallback for local development)

        var credentialOptions = new DefaultAzureCredentialOptions
        {
            ExcludeEnvironmentCredential = false,
            ExcludeManagedIdentityCredential = false,
            ExcludeAzureCliCredential = false,
            ExcludeVisualStudioCredential = false,
            ExcludeInteractiveBrowserCredential = false,
            ExcludeSharedTokenCacheCredential = false,
            ExcludeAzurePowerShellCredential = true,
            ExcludeAzureDeveloperCliCredential = true
        };

        _credential = new DefaultAzureCredential(credentialOptions);
        _logger.LogInformation("Initialized Azure credential chain");

        return _credential;
    }

    public async Task<string> GetAccessTokenAsync(string[] scopes)
    {
        var credential = GetCredential();
        var tokenRequestContext = new TokenRequestContext(scopes);
        var token = await credential.GetTokenAsync(tokenRequestContext, CancellationToken.None);
        return token.Token;
    }
}
