using System.Security.Cryptography;
using System.Text;

namespace SecureGate.Core.Auth;

/// <summary>
/// Validates PKCE (Proof Key for Code Exchange) challenges per RFC 7636.
/// Supports the S256 (SHA-256) transformation method.
/// </summary>
public class PkceValidator
{
    /// <summary>
    /// Validates that the code_verifier matches the original code_challenge.
    /// </summary>
    public bool Validate(string codeVerifier, string codeChallenge, string method = "S256")
    {
        if (string.IsNullOrWhiteSpace(codeVerifier) || string.IsNullOrWhiteSpace(codeChallenge))
            return false;

        if (!IsValidCodeVerifier(codeVerifier))
            return false;

        return method.ToUpperInvariant() switch
        {
            "S256" => ValidateS256(codeVerifier, codeChallenge),
            "PLAIN" => codeVerifier == codeChallenge,
            _ => false
        };
    }

    /// <summary>
    /// Generates a code challenge from a code verifier using S256 method.
    /// </summary>
    public string GenerateChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncode(challengeBytes);
    }

    /// <summary>
    /// Generates a cryptographically random code verifier.
    /// </summary>
    public string GenerateCodeVerifier(int length = 64)
    {
        if (length < 43 || length > 128)
            throw new ArgumentOutOfRangeException(nameof(length), "Code verifier must be 43-128 characters.");

        var bytes = RandomNumberGenerator.GetBytes(length);
        return Base64UrlEncode(bytes)[..length];
    }

    private bool ValidateS256(string codeVerifier, string codeChallenge)
    {
        var computedChallenge = GenerateChallenge(codeVerifier);
        return string.Equals(computedChallenge, codeChallenge, StringComparison.Ordinal);
    }

    private static bool IsValidCodeVerifier(string codeVerifier)
    {
        if (codeVerifier.Length < 43 || codeVerifier.Length > 128)
            return false;

        return codeVerifier.All(c =>
            char.IsLetterOrDigit(c) || c == '-' || c == '.' || c == '_' || c == '~');
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
