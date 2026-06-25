using System.Security.Cryptography;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace SecureGate.Infrastructure.KeyVault;

/// <summary>
/// Azure Key Vault service for managing RSA signing keys per tenant.
/// </summary>
public class KeyVaultService
{
    private readonly KeyClient _keyClient;
    private readonly string _keyVaultUri;

    public KeyVaultService(string keyVaultUri)
    {
        _keyVaultUri = keyVaultUri;
        _keyClient = new KeyClient(new Uri(keyVaultUri), new DefaultAzureCredential());
    }

    /// <summary>
    /// Gets or creates an RSA signing key for a tenant.
    /// </summary>
    public async Task<RSA> GetOrCreateSigningKeyAsync(string tenantId)
    {
        var keyName = $"signing-key-{tenantId}";

        try
        {
            // Try to get existing key
            var keyResponse = await _keyClient.GetKeyAsync(keyName);
            return await GetRsaFromKeyAsync(keyResponse.Value);
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            // Key doesn't exist, create new one
            return await CreateSigningKeyAsync(keyName);
        }
    }

    /// <summary>
    /// Creates a new RSA signing key in Key Vault.
    /// </summary>
    private async Task<RSA> CreateSigningKeyAsync(string keyName)
    {
        var createKeyOptions = new CreateRsaKeyOptions(keyName)
        {
            KeySize = 2048,
            KeyOperations =
            {
                KeyOperation.Sign,
                KeyOperation.Verify
            }
        };

        var keyResponse = await _keyClient.CreateRsaKeyAsync(createKeyOptions);
        return await GetRsaFromKeyAsync(keyResponse.Value);
    }

    /// <summary>
    /// Gets RSA parameters from Key Vault key for local JWT signing.
    /// Note: For production, use CryptographyClient to sign in Key Vault.
    /// </summary>
    private async Task<RSA> GetRsaFromKeyAsync(KeyVaultKey key)
    {
        var rsaKey = key.Key;

        // For public operations only (verification)
        // Private key operations should use CryptographyClient
        var rsa = RSA.Create();

        var rsaParams = new RSAParameters
        {
            Modulus = rsaKey.N,
            Exponent = rsaKey.E
        };

        rsa.ImportParameters(rsaParams);
        return rsa;
    }

    /// <summary>
    /// Signs data using Key Vault (private key never leaves Key Vault).
    /// </summary>
    public async Task<byte[]> SignAsync(string keyName, byte[] data)
    {
        var cryptoClient = _keyClient.GetCryptographyClient(keyName);

        // Hash the data first
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);

        var signResult = await cryptoClient.SignAsync(SignatureAlgorithm.RS256, hash);
        return signResult.Signature;
    }

    /// <summary>
    /// Verifies a signature using Key Vault.
    /// </summary>
    public async Task<bool> VerifyAsync(string keyName, byte[] data, byte[] signature)
    {
        var cryptoClient = _keyClient.GetCryptographyClient(keyName);

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);

        var verifyResult = await cryptoClient.VerifyAsync(SignatureAlgorithm.RS256, hash, signature);
        return verifyResult.IsValid;
    }

    /// <summary>
    /// Rotates a tenant's signing key.
    /// </summary>
    public async Task<RSA> RotateKeyAsync(string tenantId)
    {
        var keyName = $"signing-key-{tenantId}";

        // Create new version of the key
        return await CreateSigningKeyAsync(keyName);
    }

    /// <summary>
    /// Gets the JWKS (JSON Web Key Set) for public key distribution.
    /// </summary>
    public async Task<object> GetJwksAsync(string tenantId)
    {
        var keyName = $"signing-key-{tenantId}";

        try
        {
            var keyResponse = await _keyClient.GetKeyAsync(keyName);
            var key = keyResponse.Value.Key;

            return new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        kid = keyResponse.Value.Properties.Version,
                        n = Convert.ToBase64String(key.N),
                        e = Convert.ToBase64String(key.E),
                        alg = "RS256"
                    }
                }
            };
        }
        catch
        {
            return new { keys = Array.Empty<object>() };
        }
    }
}
