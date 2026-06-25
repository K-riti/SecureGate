using Microsoft.AspNetCore.Mvc;
using SecureGate.API.Middleware;
using SecureGate.Core.Auth;
using SecureGate.Core.Tenancy;

namespace SecureGate.API.Controllers;

/// <summary>
/// OAuth 2.0 Authorization endpoint (RFC 6749 Section 3.1).
/// </summary>
[ApiController]
[Route("oauth")]
public class AuthorizeController : ControllerBase
{
    private readonly TenantConfigService _tenantService;
    private readonly PkceValidator _pkceValidator;
    private readonly IAuthorizationCodeStore _codeStore;

    public AuthorizeController(
        TenantConfigService tenantService,
        PkceValidator pkceValidator,
        IAuthorizationCodeStore codeStore)
    {
        _tenantService = tenantService;
        _pkceValidator = pkceValidator;
        _codeStore = codeStore;
    }

    /// <summary>
    /// Authorization endpoint - initiates OAuth 2.0 Authorization Code flow.
    /// </summary>
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "response_type")] string responseType,
        [FromQuery(Name = "client_id")] string clientId,
        [FromQuery(Name = "redirect_uri")] string redirectUri,
        [FromQuery(Name = "scope")] string? scope,
        [FromQuery(Name = "state")] string? state,
        [FromQuery(Name = "code_challenge")] string? codeChallenge,
        [FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod)
    {
        var tenantId = HttpContext.GetTenantId();
        if (string.IsNullOrEmpty(tenantId))
            return BadRequest(new { error = "invalid_request", error_description = "Tenant not resolved" });

        // Validate response_type
        if (responseType != "code")
            return BadRequest(new { error = "unsupported_response_type" });

        // Validate client
        if (!await _tenantService.ValidateClientAsync(tenantId, clientId))
            return BadRequest(new { error = "invalid_client" });

        // Validate redirect_uri
        if (!await _tenantService.ValidateRedirectUriAsync(tenantId, redirectUri))
            return BadRequest(new { error = "invalid_request", error_description = "Invalid redirect_uri" });

        // PKCE is required for public clients
        if (string.IsNullOrEmpty(codeChallenge))
            return BadRequest(new { error = "invalid_request", error_description = "code_challenge required" });

        if (codeChallengeMethod != "S256")
            return BadRequest(new { error = "invalid_request", error_description = "code_challenge_method must be S256" });

        // Store authorization request for later (after user authentication)
        var authRequest = new AuthorizationRequest
        {
            TenantId = tenantId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scope = scope ?? "openid",
            State = state,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            CreatedAt = DateTime.UtcNow
        };

        await _codeStore.StoreRequestAsync(authRequest);

        // In production, redirect to login page or external IdP (Azure AD B2C)
        // For now, return the request details
        return Ok(new
        {
            message = "Authorization request received. Redirect to login.",
            request_id = authRequest.RequestId,
            tenant_id = tenantId,
            client_id = clientId
        });
    }

    /// <summary>
    /// Callback endpoint after user authentication.
    /// </summary>
    [HttpPost("authorize/callback")]
    public async Task<IActionResult> AuthorizeCallback([FromBody] AuthCallbackRequest request)
    {
        var authRequest = await _codeStore.GetRequestAsync(request.RequestId);
        if (authRequest == null)
            return BadRequest(new { error = "invalid_request" });

        // Generate authorization code
        var code = new AuthorizationCode
        {
            Code = Guid.NewGuid().ToString("N"),
            TenantId = authRequest.TenantId,
            ClientId = authRequest.ClientId,
            UserId = request.UserId,
            RedirectUri = authRequest.RedirectUri,
            Scope = authRequest.Scope,
            CodeChallenge = authRequest.CodeChallenge,
            CodeChallengeMethod = authRequest.CodeChallengeMethod,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10)
        };

        await _codeStore.StoreCodeAsync(code);

        // Build redirect URL with code
        var redirectUrl = $"{authRequest.RedirectUri}?code={code.Code}";
        if (!string.IsNullOrEmpty(authRequest.State))
            redirectUrl += $"&state={Uri.EscapeDataString(authRequest.State)}";

        return Ok(new { redirect_uri = redirectUrl, code = code.Code });
    }
}

public class AuthCallbackRequest
{
    public string RequestId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
}

public class AuthorizationRequest
{
    public string RequestId { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string? State { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class AuthorizationCode
{
    public string Code { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
}

public interface IAuthorizationCodeStore
{
    Task StoreRequestAsync(AuthorizationRequest request);
    Task<AuthorizationRequest?> GetRequestAsync(string requestId);
    Task StoreCodeAsync(AuthorizationCode code);
    Task<AuthorizationCode?> GetCodeAsync(string code);
    Task MarkCodeUsedAsync(string code);
}
