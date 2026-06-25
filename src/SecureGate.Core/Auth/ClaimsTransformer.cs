using System.Security.Claims;

namespace SecureGate.Core.Auth;

/// <summary>
/// Transforms and enriches claims from various identity providers.
/// </summary>
public class ClaimsTransformer
{
    private readonly List<ClaimTransformationRule> _rules = new();

    /// <summary>
    /// Adds a transformation rule.
    /// </summary>
    public ClaimsTransformer AddRule(string sourceClaim, string targetClaim, Func<string, string>? transform = null)
    {
        _rules.Add(new ClaimTransformationRule
        {
            SourceClaimType = sourceClaim,
            TargetClaimType = targetClaim,
            Transform = transform ?? (value => value)
        });
        return this;
    }

    /// <summary>
    /// Transforms claims according to configured rules.
    /// </summary>
    public ClaimsPrincipal Transform(ClaimsPrincipal principal, string tenantId)
    {
        var identity = principal.Identity as ClaimsIdentity;
        if (identity == null)
            return principal;

        var newClaims = new List<Claim>();

        // Always add tenant_id
        if (!identity.HasClaim(c => c.Type == "tenant_id"))
        {
            newClaims.Add(new Claim("tenant_id", tenantId));
        }

        // Apply transformation rules
        foreach (var rule in _rules)
        {
            var sourceClaim = identity.FindFirst(rule.SourceClaimType);
            if (sourceClaim != null)
            {
                var transformedValue = rule.Transform(sourceClaim.Value);
                newClaims.Add(new Claim(rule.TargetClaimType, transformedValue));
            }
            else if (rule.DefaultValue != null)
            {
                newClaims.Add(new Claim(rule.TargetClaimType, rule.DefaultValue));
            }
        }

        // Apply standard transformations
        ApplyStandardTransformations(identity, newClaims);

        identity.AddClaims(newClaims);
        return principal;
    }

    /// <summary>
    /// Creates a transformer with default rules for common IdP claim mappings.
    /// </summary>
    public static ClaimsTransformer CreateDefault()
    {
        return new ClaimsTransformer()
            // Azure AD B2C mappings
            .AddRule("oid", ClaimTypes.NameIdentifier)
            .AddRule("emails", "email", value => value.TrimStart('[').TrimEnd(']').Trim('"'))
            .AddRule("name", ClaimTypes.Name)
            .AddRule("given_name", ClaimTypes.GivenName)
            .AddRule("family_name", ClaimTypes.Surname)
            // Google mappings
            .AddRule("sub", ClaimTypes.NameIdentifier)
            .AddRule("email", "email")
            // Generic OIDC mappings
            .AddRule("preferred_username", "username")
            .AddRule("picture", "avatar_url");
    }

    private static void ApplyStandardTransformations(ClaimsIdentity identity, List<Claim> newClaims)
    {
        // Ensure 'sub' claim exists (required for OIDC)
        if (!identity.HasClaim(c => c.Type == "sub"))
        {
            var nameId = identity.FindFirst(ClaimTypes.NameIdentifier);
            if (nameId != null)
            {
                newClaims.Add(new Claim("sub", nameId.Value));
            }
        }

        // Normalize email claim
        var email = identity.FindFirst(ClaimTypes.Email) ?? 
                    identity.FindFirst("email") ??
                    identity.FindFirst("emails");
        if (email != null && !identity.HasClaim(c => c.Type == "email"))
        {
            var emailValue = email.Value.TrimStart('[').TrimEnd(']').Trim('"');
            newClaims.Add(new Claim("email", emailValue));
        }

        // Normalize name claim
        var name = identity.FindFirst(ClaimTypes.Name) ?? identity.FindFirst("name");
        if (name != null && !identity.HasClaim(c => c.Type == "name"))
        {
            newClaims.Add(new Claim("name", name.Value));
        }

        // Add authentication time
        newClaims.Add(new Claim("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
    }
}

public class ClaimTransformationRule
{
    public string SourceClaimType { get; set; } = string.Empty;
    public string TargetClaimType { get; set; } = string.Empty;
    public Func<string, string> Transform { get; set; } = value => value;
    public string? DefaultValue { get; set; }
}
