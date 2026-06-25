using Microsoft.AspNetCore.Mvc;
using SecureGate.API.Middleware;
using SecureGate.Core.Auth;
using SecureGate.Core.Tenancy;
using System.Security.Cryptography;

namespace SecureGate.API.Controllers;

/// <summary>
/// OAuth 2.0 Token endpoint (RFC 6749 Section 3.2).
/// </summary>
[ApiController]
[Route("oauth")]
public class TokenController : ControllerBase
{
    private readonly TenantConfigService _tenantService;
    private readonly PkceValidator _pkceValidator;
    private readonly IAuthorizationCodeStore _codeStore;
    private readonly RefreshTokenRotator _refreshTokenRotator;
    private readonly JwtIssuer _jwtIssuer;

    public TokenController(
        TenantConfigService tenantService,
        PkceValidator pkceValidator,
        IAuthorizationCodeStore codeStore,
        RefreshTokenRotator refreshTokenRotator,
        JwtIssuer jwtIssuer)
    {
        _tenantService = tenantService;
        _pkceValidator = pkceValidator;
        _codeStore = codeStore;
        _refreshTokenRotator = refreshTokenRotator;
        _jwtIssuer = jwtIssuer;
    }

    /// <summary>
    /// Token endpoint - exchanges authorization code or refresh token for tokens.
    /// </summary>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        var tenantId = HttpContext.GetTenantId();
        if (string.IsNullOrEmpty(tenantId))
            return BadRequest(new TokenErrorResponse("invalid_request", "Tenant not resolved"));

        return request.GrantType switch
        {
            "authorization_code" => await HandleAuthorizationCodeGrant(request, tenantId),
            "refresh_token" => await HandleRefreshTokenGrant(request, tenantId),
            _ => BadRequest(new TokenErrorResponse("unsupported_grant_type"))
        };
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrant(TokenRequest request, string tenantId)
    {
        if (string.IsNullOrEmpty(request.Code))
            return BadRequest(new TokenErrorResponse("invalid_request", "code is required"));

        if (string.IsNullOrEmpty(request.CodeVerifier))
            return BadRequest(new TokenErrorResponse("invalid_request", "code_verifier is required"));

        // Get and validate authorization code
        var authCode = await _codeStore.GetCodeAsync(request.Code);
        if (authCode == null || authCode.IsUsed || authCode.ExpiresAt < DateTime.UtcNow)
            return BadRequest(new TokenErrorResponse("invalid_grant", "Invalid or expired code"));

        // Validate client
        if (authCode.ClientId != request.ClientId)
            return BadRequest(new TokenErrorResponse("invalid_client"));

        // Validate PKCE
        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (!_pkceValidator.Validate(request.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod ?? "S256"))
                return BadRequest(new TokenErrorResponse("invalid_grant", "PKCE verification failed"));
        }

        // Mark code as used
        await _codeStore.MarkCodeUsedAsync(request.Code);

        // Issue tokens
        var roles = new[] { "user" }; // In production, load from user store
        var scopes = authCode.Scope.Split(' ');

        var accessToken = _jwtIssuer.IssueAccessToken(authCode.UserId, tenantId, roles, scopes);
        var idToken = _jwtIssuer.IssueIdToken(authCode.UserId, tenantId);
        var refreshToken = await _refreshTokenRotator.IssueAsync(authCode.UserId, tenantId, authCode.ClientId);

        return Ok(new TokenResponse
        {
            AccessToken = accessToken.Token,
            TokenType = "Bearer",
            ExpiresIn = (int)(accessToken.ExpiresAt - DateTime.UtcNow).TotalSeconds,
            RefreshToken = refreshToken.Token,
            IdToken = idToken.Token,
            Scope = authCode.Scope
        });
    }

    private async Task<IActionResult> HandleRefreshTokenGrant(TokenRequest request, string tenantId)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
            return BadRequest(new TokenErrorResponse("invalid_request", "refresh_token is required"));

        var rotationResult = await _refreshTokenRotator.RotateAsync(request.RefreshToken);
        if (!rotationResult.IsSuccess)
            return BadRequest(new TokenErrorResponse("invalid_grant", rotationResult.Error));

        var newRefreshToken = rotationResult.NewToken!;

        // Issue new access token
        var roles = new[] { "user" };
        var accessToken = _jwtIssuer.IssueAccessToken(newRefreshToken.UserId, tenantId, roles);

        return Ok(new TokenResponse
        {
            AccessToken = accessToken.Token,
            TokenType = "Bearer",
            ExpiresIn = (int)(accessToken.ExpiresAt - DateTime.UtcNow).TotalSeconds,
            RefreshToken = newRefreshToken.Token
        });
    }
}

public class TokenRequest
{
    [FromForm(Name = "grant_type")]
    public string GrantType { get; set; } = string.Empty;

    [FromForm(Name = "code")]
    public string? Code { get; set; }

    [FromForm(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }

    [FromForm(Name = "client_id")]
    public string? ClientId { get; set; }

    [FromForm(Name = "client_secret")]
    public string? ClientSecret { get; set; }

    [FromForm(Name = "code_verifier")]
    public string? CodeVerifier { get; set; }

    [FromForm(Name = "refresh_token")]
    public string? RefreshToken { get; set; }

    [FromForm(Name = "scope")]
    public string? Scope { get; set; }
}

public class TokenResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; }
    public string? RefreshToken { get; set; }
    public string? IdToken { get; set; }
    public string? Scope { get; set; }
}

public class TokenErrorResponse
{
    public string Error { get; set; }
    public string? ErrorDescription { get; set; }

    public TokenErrorResponse(string error, string? description = null)
    {
        Error = error;
        ErrorDescription = description;
    }
}
