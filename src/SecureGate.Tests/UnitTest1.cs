using SecureGate.Core.Auth;
using SecureGate.Core.Users;

namespace SecureGate.Tests;

public class PkceValidatorTests
{
    private readonly PkceValidator _validator = new();

    [Fact]
    public void GenerateCodeVerifier_ReturnsValidLength()
    {
        var verifier = _validator.GenerateCodeVerifier(64);
        Assert.Equal(64, verifier.Length);
    }

    [Fact]
    public void GenerateChallenge_ProducesConsistentResult()
    {
        var verifier = "test-code-verifier-that-is-at-least-43-characters-long";
        var challenge1 = _validator.GenerateChallenge(verifier);
        var challenge2 = _validator.GenerateChallenge(verifier);

        Assert.Equal(challenge1, challenge2);
    }

    [Fact]
    public void Validate_WithCorrectVerifier_ReturnsTrue()
    {
        var verifier = _validator.GenerateCodeVerifier(64);
        var challenge = _validator.GenerateChallenge(verifier);

        var result = _validator.Validate(verifier, challenge, "S256");

        Assert.True(result);
    }

    [Fact]
    public void Validate_WithIncorrectVerifier_ReturnsFalse()
    {
        var verifier = _validator.GenerateCodeVerifier(64);
        var challenge = _validator.GenerateChallenge(verifier);
        var wrongVerifier = _validator.GenerateCodeVerifier(64);

        var result = _validator.Validate(wrongVerifier, challenge, "S256");

        Assert.False(result);
    }

    [Fact]
    public void Validate_WithNullInput_ReturnsFalse()
    {
        Assert.False(_validator.Validate(null!, "challenge", "S256"));
        Assert.False(_validator.Validate("verifier", null!, "S256"));
    }
}

public class CredentialHasherTests
{
    private readonly CredentialHasher _hasher = new();

    [Fact]
    public void HashPassword_ProducesDifferentHashesForSamePassword()
    {
        var password = "SecurePassword123!";

        var hash1 = _hasher.HashPassword(password);
        var hash2 = _hasher.HashPassword(password);

        Assert.NotEqual(hash1, hash2); // Different salts
    }

    [Fact]
    public void VerifyPassword_WithCorrectPassword_ReturnsTrue()
    {
        var password = "SecurePassword123!";
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(password, hash);

        Assert.True(result);
    }

    [Fact]
    public void VerifyPassword_WithIncorrectPassword_ReturnsFalse()
    {
        var password = "SecurePassword123!";
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword("WrongPassword!", hash);

        Assert.False(result);
    }

    [Fact]
    public void VerifyPassword_WithNullInput_ReturnsFalse()
    {
        Assert.False(_hasher.VerifyPassword(null!, "hash"));
        Assert.False(_hasher.VerifyPassword("password", null!));
    }

    [Fact]
    public void NeedsRehash_WithCurrentIterations_ReturnsFalse()
    {
        var password = "TestPassword";
        var hash = _hasher.HashPassword(password);

        var result = _hasher.NeedsRehash(hash);

        Assert.False(result);
    }
}

public class JwtIssuerTests
{
    [Fact]
    public void IssueAccessToken_ReturnsValidToken()
    {
        var settings = new JwtSettings
        {
            Issuer = "https://test.local",
            Audience = "test-api",
            KeyId = "test-key",
            AccessTokenLifetimeMinutes = 15
        };

        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var issuer = new JwtIssuer(settings, rsa);

        var result = issuer.IssueAccessToken("user-123", "tenant-1", new[] { "user" });

        Assert.NotEmpty(result.Token);
        Assert.Equal("Bearer", result.TokenType);
        Assert.True(result.ExpiresAt > DateTime.UtcNow);
    }
}
