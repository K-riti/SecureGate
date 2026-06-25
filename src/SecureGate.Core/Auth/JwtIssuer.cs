using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace SecureGate.Core.Auth;

/// <summary>
/// Issues RS256-signed JWT access tokens and ID tokens.
/// </summary>
public class JwtIssuer
{
    private readonly JwtSettings _settings;
    private readonly RsaSecurityKey _signingKey;

    public JwtIssuer(JwtSettings settings, RSA rsaKey)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _signingKey = new RsaSecurityKey(rsaKey) { KeyId = settings.KeyId };
    }

    /// <summary>
    /// Issues an access token for the specified user and tenant.
    /// </summary>
    public TokenResult IssueAccessToken(string userId, string tenantId, IEnumerable<string> roles, IEnumerable<string>? scopes = null)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(_settings.AccessTokenLifetimeMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("tenant_id", tenantId),
            new("token_type", "access_token")
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
            claims.Add(new Claim("roles", role));
        }

        if (scopes?.Any() == true)
        {
            claims.Add(new Claim("scope", string.Join(" ", scopes)));
        }

        var token = CreateToken(claims, expires);

        return new TokenResult
        {
            Token = token,
            ExpiresAt = expires,
            TokenType = "Bearer"
        };
    }

    /// <summary>
    /// Issues an ID token containing user identity claims.
    /// </summary>
    public TokenResult IssueIdToken(string userId, string tenantId, string? email = null, string? name = null)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(_settings.IdTokenLifetimeMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("tenant_id", tenantId),
            new("token_type", "id_token")
        };

        if (!string.IsNullOrEmpty(email))
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, email));

        if (!string.IsNullOrEmpty(name))
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, name));

        var token = CreateToken(claims, expires);

        return new TokenResult
        {
            Token = token,
            ExpiresAt = expires,
            TokenType = "Bearer"
        };
    }

    private string CreateToken(IEnumerable<Claim> claims, DateTime expires)
    {
        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _settings.Issuer,
            Audience = _settings.Audience,
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            NotBefore = DateTime.UtcNow,
            SigningCredentials = credentials
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }
}

public class JwtSettings
{
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    public int IdTokenLifetimeMinutes { get; set; } = 60;
}

public class TokenResult
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string TokenType { get; set; } = "Bearer";
}
