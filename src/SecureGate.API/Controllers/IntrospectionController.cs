using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureGate.API.Middleware;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SecureGate.API.Controllers;

/// <summary>
/// Token introspection endpoint (RFC 7662) and user info endpoint.
/// </summary>
[ApiController]
[Route("oauth")]
public class IntrospectionController : ControllerBase
{
    /// <summary>
    /// Token introspection endpoint - validates and returns token metadata.
    /// </summary>
    [HttpPost("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    public IActionResult Introspect([FromForm] string token, [FromForm] string? token_type_hint = null)
    {
        if (string.IsNullOrEmpty(token))
            return Ok(new { active = false });

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
                return Ok(new { active = false });

            var jwt = handler.ReadJwtToken(token);

            // Check expiration
            if (jwt.ValidTo < DateTime.UtcNow)
                return Ok(new { active = false });

            return Ok(new
            {
                active = true,
                sub = jwt.Subject,
                client_id = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value,
                tenant_id = jwt.Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value,
                scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value,
                exp = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds(),
                iat = new DateTimeOffset(jwt.IssuedAt).ToUnixTimeSeconds(),
                iss = jwt.Issuer,
                aud = jwt.Audiences.FirstOrDefault(),
                token_type = "Bearer"
            });
        }
        catch
        {
            return Ok(new { active = false });
        }
    }

    /// <summary>
    /// Token revocation endpoint (RFC 7009).
    /// </summary>
    [HttpPost("revoke")]
    [Consumes("application/x-www-form-urlencoded")]
    public IActionResult Revoke([FromForm] string token, [FromForm] string? token_type_hint = null)
    {
        // In production, add to revocation list or delete from store
        // Always return 200 OK per RFC 7009
        return Ok();
    }

    /// <summary>
    /// UserInfo endpoint - returns authenticated user's claims.
    /// </summary>
    [HttpGet("userinfo")]
    [Authorize]
    public IActionResult UserInfo()
    {
        var claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);

        return Ok(new
        {
            sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value,
            tenant_id = User.FindFirst("tenant_id")?.Value,
            email = User.FindFirst(ClaimTypes.Email)?.Value ?? User.FindFirst("email")?.Value,
            name = User.FindFirst(ClaimTypes.Name)?.Value ?? User.FindFirst("name")?.Value,
            roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray()
        });
    }
}

/// <summary>
/// Protected resource controller - demonstrates RBAC.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ProtectedController : ControllerBase
{
    /// <summary>
    /// Get current user info - requires authentication.
    /// </summary>
    [HttpGet("me")]
    public IActionResult GetMe()
    {
        return Ok(new
        {
            user_id = User.FindFirst("sub")?.Value,
            tenant_id = User.FindFirst("tenant_id")?.Value,
            roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray(),
            message = "You are authenticated!"
        });
    }

    /// <summary>
    /// Admin only endpoint - requires 'admin' role.
    /// </summary>
    [HttpGet("admin")]
    [Authorize(Policy = "Admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new { message = "Welcome, Admin!" });
    }

    /// <summary>
    /// User endpoint - requires 'user' or 'admin' role.
    /// </summary>
    [HttpGet("user")]
    [Authorize(Policy = "User")]
    public IActionResult UserAccess()
    {
        return Ok(new { message = "Welcome, User!" });
    }
}
