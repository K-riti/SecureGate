namespace SecureGate.Core.Tenancy;

/// <summary>
/// Manages tenant-specific configuration for multi-tenant OAuth.
/// </summary>
public class TenantConfigService
{
    private readonly ITenantConfigStore _store;

    public TenantConfigService(ITenantConfigStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public async Task<TenantConfig?> GetConfigAsync(string tenantId)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            return null;

        return await _store.GetByIdAsync(tenantId);
    }

    public async Task<TenantConfig?> GetByDomainAsync(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return null;

        return await _store.GetByDomainAsync(domain.ToLowerInvariant());
    }

    public async Task<bool> ValidateRedirectUriAsync(string tenantId, string redirectUri)
    {
        var config = await GetConfigAsync(tenantId);
        if (config == null) return false;

        return config.AllowedRedirectUris.Any(uri =>
            string.Equals(uri, redirectUri, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<bool> ValidateClientAsync(string tenantId, string clientId, string? clientSecret = null)
    {
        var config = await GetConfigAsync(tenantId);
        if (config == null) return false;

        var client = config.RegisteredClients.FirstOrDefault(c => c.ClientId == clientId);
        if (client == null) return false;

        if (client.IsPublicClient) return true;

        return !string.IsNullOrEmpty(clientSecret) &&
               string.Equals(client.ClientSecretHash, clientSecret, StringComparison.Ordinal);
    }
}

public class TenantConfig
{
    public string TenantId { get; set; } = string.Empty;
    public string TenantName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public List<string> AllowedRedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new() { "openid", "profile", "email" };
    public List<RegisteredClient> RegisteredClients { get; set; } = new();
    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    public int RefreshTokenLifetimeDays { get; set; } = 30;
    public ExternalIdpConfig? ExternalIdp { get; set; }
    public List<ClaimMappingRule> ClaimMappings { get; set; } = new();
}

public class RegisteredClient
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string? ClientSecretHash { get; set; }
    public bool IsPublicClient { get; set; } = true;
    public List<string> AllowedGrantTypes { get; set; } = new() { "authorization_code" };
    public List<string> AllowedScopes { get; set; } = new();
}

public class ExternalIdpConfig
{
    public string Provider { get; set; } = "AzureAdB2C";
    public string Instance { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string SignUpSignInPolicyId { get; set; } = string.Empty;
}

public class ClaimMappingRule
{
    public string SourceClaim { get; set; } = string.Empty;
    public string TargetClaim { get; set; } = string.Empty;
    public string? DefaultValue { get; set; }
}

public interface ITenantConfigStore
{
    Task<TenantConfig?> GetByIdAsync(string tenantId);
    Task<TenantConfig?> GetByDomainAsync(string domain);
    Task<IEnumerable<TenantConfig>> GetAllAsync();
    Task SaveAsync(TenantConfig config);
}
