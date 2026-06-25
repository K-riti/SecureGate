using System.Security.Cryptography;

namespace SecureGate.Core.Auth;

/// <summary>
/// Manages refresh token rotation with family tracking for replay detection (RFC 6819).
/// </summary>
public class RefreshTokenRotator
{
    private readonly IRefreshTokenStore _tokenStore;
    private readonly RefreshTokenSettings _settings;

    public RefreshTokenRotator(IRefreshTokenStore tokenStore, RefreshTokenSettings settings)
    {
        _tokenStore = tokenStore ?? throw new ArgumentNullException(nameof(tokenStore));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public async Task<RefreshToken> IssueAsync(string userId, string tenantId, string? clientId = null)
    {
        var token = new RefreshToken
        {
            Token = GenerateSecureToken(),
            UserId = userId,
            TenantId = tenantId,
            ClientId = clientId,
            FamilyId = Guid.NewGuid().ToString(),
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(_settings.LifetimeDays),
            IsRevoked = false
        };

        await _tokenStore.StoreAsync(token);
        return token;
    }

    public async Task<RefreshTokenRotationResult> RotateAsync(string currentToken)
    {
        var existingToken = await _tokenStore.GetAsync(currentToken);

        if (existingToken == null)
            return RefreshTokenRotationResult.Failed("Token not found");

        if (existingToken.IsRevoked)
        {
            await _tokenStore.RevokeFamilyAsync(existingToken.FamilyId);
            return RefreshTokenRotationResult.Failed("Token revoked. Possible replay attack.");
        }

        if (existingToken.ExpiresAt < DateTime.UtcNow)
            return RefreshTokenRotationResult.Failed("Token expired");

        existingToken.IsRevoked = true;
        existingToken.RevokedAt = DateTime.UtcNow;
        await _tokenStore.UpdateAsync(existingToken);

        var newToken = new RefreshToken
        {
            Token = GenerateSecureToken(),
            UserId = existingToken.UserId,
            TenantId = existingToken.TenantId,
            ClientId = existingToken.ClientId,
            FamilyId = existingToken.FamilyId,
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(_settings.LifetimeDays),
            IsRevoked = false,
            PreviousToken = currentToken
        };

        await _tokenStore.StoreAsync(newToken);
        return RefreshTokenRotationResult.Success(newToken);
    }

    public async Task RevokeAsync(string token, bool revokeFamily = false)
    {
        var existingToken = await _tokenStore.GetAsync(token);
        if (existingToken == null) return;

        if (revokeFamily)
            await _tokenStore.RevokeFamilyAsync(existingToken.FamilyId);
        else
        {
            existingToken.IsRevoked = true;
            existingToken.RevokedAt = DateTime.UtcNow;
            await _tokenStore.UpdateAsync(existingToken);
        }
    }

    private static string GenerateSecureToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}

public class RefreshToken
{
    public string Token { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public string? ClientId { get; set; }
    public string FamilyId { get; set; } = string.Empty;
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? PreviousToken { get; set; }
}

public class RefreshTokenSettings
{
    public int LifetimeDays { get; set; } = 30;
}

public class RefreshTokenRotationResult
{
    public bool IsSuccess { get; private set; }
    public RefreshToken? NewToken { get; private set; }
    public string? Error { get; private set; }

    public static RefreshTokenRotationResult Success(RefreshToken token) =>
        new() { IsSuccess = true, NewToken = token };

    public static RefreshTokenRotationResult Failed(string error) =>
        new() { IsSuccess = false, Error = error };
}

public interface IRefreshTokenStore
{
    Task StoreAsync(RefreshToken token);
    Task<RefreshToken?> GetAsync(string token);
    Task UpdateAsync(RefreshToken token);
    Task RevokeFamilyAsync(string familyId);
}
