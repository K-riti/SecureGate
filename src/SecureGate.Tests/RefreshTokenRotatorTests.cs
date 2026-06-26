using SecureGate.Core.Auth;

namespace SecureGate.Tests;

public class RefreshTokenRotatorTests
{
    private readonly InMemoryRefreshTokenStore _tokenStore;
    private readonly RefreshTokenRotator _rotator;
    private readonly RefreshTokenSettings _settings;

    public RefreshTokenRotatorTests()
    {
        _tokenStore = new InMemoryRefreshTokenStore();
        _settings = new RefreshTokenSettings { LifetimeDays = 30 };
        _rotator = new RefreshTokenRotator(_tokenStore, _settings);
    }

    [Fact]
    public async Task IssueAsync_CreatesValidToken()
    {
        var userId = "user-123";
        var tenantId = "tenant-1";

        var token = await _rotator.IssueAsync(userId, tenantId);

        Assert.NotNull(token);
        Assert.NotEmpty(token.Token);
        Assert.Equal(userId, token.UserId);
        Assert.Equal(tenantId, token.TenantId);
        Assert.NotEmpty(token.FamilyId);
        Assert.False(token.IsRevoked);
        Assert.True(token.ExpiresAt > DateTime.UtcNow);
    }

    [Fact]
    public async Task IssueAsync_StoresTokenInStore()
    {
        var token = await _rotator.IssueAsync("user-123", "tenant-1");

        var storedToken = await _tokenStore.GetAsync(token.Token);

        Assert.NotNull(storedToken);
        Assert.Equal(token.Token, storedToken.Token);
    }

    [Fact]
    public async Task RotateAsync_WithValidToken_ReturnsNewToken()
    {
        var originalToken = await _rotator.IssueAsync("user-123", "tenant-1");

        var result = await _rotator.RotateAsync(originalToken.Token);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.NewToken);
        Assert.NotEqual(originalToken.Token, result.NewToken.Token);
        Assert.Equal(originalToken.FamilyId, result.NewToken.FamilyId);
        Assert.Equal(originalToken.UserId, result.NewToken.UserId);
    }

    [Fact]
    public async Task RotateAsync_MarksOldTokenAsUsed()
    {
        var originalToken = await _rotator.IssueAsync("user-123", "tenant-1");

        await _rotator.RotateAsync(originalToken.Token);

        var oldToken = await _tokenStore.GetAsync(originalToken.Token);
        Assert.NotNull(oldToken);
        Assert.True(oldToken.IsRevoked);
        Assert.NotNull(oldToken.RevokedAt);
    }

    [Fact]
    public async Task RotateAsync_WithNonExistentToken_ReturnsFailed()
    {
        var result = await _rotator.RotateAsync("non-existent-token");

        Assert.False(result.IsSuccess);
        Assert.Contains("not found", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RotateAsync_WithExpiredToken_ReturnsFailed()
    {
        var token = await _rotator.IssueAsync("user-123", "tenant-1");

        // Manually expire the token
        var storedToken = await _tokenStore.GetAsync(token.Token);
        storedToken!.ExpiresAt = DateTime.UtcNow.AddDays(-1);
        await _tokenStore.UpdateAsync(storedToken);

        var result = await _rotator.RotateAsync(token.Token);

        Assert.False(result.IsSuccess);
        Assert.Contains("expired", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RotateAsync_ReplayAttack_RevokesEntireFamily()
    {
        // Issue initial token
        var originalToken = await _rotator.IssueAsync("user-123", "tenant-1");
        var familyId = originalToken.FamilyId;

        // Legitimate rotation
        var rotationResult = await _rotator.RotateAsync(originalToken.Token);
        Assert.True(rotationResult.IsSuccess);
        var newToken = rotationResult.NewToken!;

        // Simulate replay attack - reuse the old token
        var replayResult = await _rotator.RotateAsync(originalToken.Token);

        // Replay should fail
        Assert.False(replayResult.IsSuccess);
        Assert.Contains("replay", replayResult.Error, StringComparison.OrdinalIgnoreCase);

        // Entire family should be revoked
        var familyTokens = _tokenStore.GetByFamily(familyId);
        Assert.All(familyTokens, t => Assert.True(t.IsRevoked));
    }

    [Fact]
    public async Task RevokeAsync_RevokesToken()
    {
        var token = await _rotator.IssueAsync("user-123", "tenant-1");

        await _rotator.RevokeAsync(token.Token);

        var storedToken = await _tokenStore.GetAsync(token.Token);
        Assert.NotNull(storedToken);
        Assert.True(storedToken.IsRevoked);
    }

    [Fact]
    public async Task RevokeAsync_WithFamilyFlag_RevokesAllFamilyTokens()
    {
        // Issue and rotate to create a family chain
        var token1 = await _rotator.IssueAsync("user-123", "tenant-1");
        var result = await _rotator.RotateAsync(token1.Token);
        var token2 = result.NewToken!;

        // Revoke entire family
        await _rotator.RevokeAsync(token2.Token, revokeFamily: true);

        // All tokens in family should be revoked
        var familyTokens = _tokenStore.GetByFamily(token1.FamilyId);
        Assert.All(familyTokens, t => Assert.True(t.IsRevoked));
    }

    [Fact]
    public async Task IssueAsync_WithClientId_IncludesClientId()
    {
        var token = await _rotator.IssueAsync("user-123", "tenant-1", "client-app");

        Assert.Equal("client-app", token.ClientId);
    }

    [Fact]
    public void Constructor_WithNullStore_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => 
            new RefreshTokenRotator(null!, _settings));
    }

    [Fact]
    public void Constructor_WithNullSettings_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => 
            new RefreshTokenRotator(_tokenStore, null!));
    }
}

/// <summary>
/// In-memory implementation of IRefreshTokenStore for testing.
/// </summary>
internal class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly Dictionary<string, RefreshToken> _tokens = new();

    public Task StoreAsync(RefreshToken token)
    {
        _tokens[token.Token] = token;
        return Task.CompletedTask;
    }

    public Task<RefreshToken?> GetAsync(string token)
    {
        _tokens.TryGetValue(token, out var result);
        return Task.FromResult(result);
    }

    public Task UpdateAsync(RefreshToken token)
    {
        _tokens[token.Token] = token;
        return Task.CompletedTask;
    }

    public Task RevokeFamilyAsync(string familyId)
    {
        foreach (var token in _tokens.Values.Where(t => t.FamilyId == familyId))
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
        return Task.CompletedTask;
    }

    public IEnumerable<RefreshToken> GetByFamily(string familyId)
    {
        return _tokens.Values.Where(t => t.FamilyId == familyId).ToList();
    }
}
