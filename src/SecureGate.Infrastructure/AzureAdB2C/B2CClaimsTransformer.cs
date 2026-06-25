using System.Security.Claims;
using SecureGate.Core.Tenancy;

namespace SecureGate.Infrastructure.AzureAdB2C;

/// <summary>
/// Transforms Azure AD B2C claims to SecureGate tenant-specific claims.
/// </summary>
public class B2CClaimsTransformer
{
    private readonly TenantConfigService _tenantService;

    public B2CClaimsTransformer(TenantConfigService tenantService)
    {
        _tenantService = tenantService;
    }

    /// <summary>
    /// Transforms B2C claims according to tenant claim mapping rules.
    /// </summary>
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal, string tenantId)
    {
        var tenantConfig = await _tenantService.GetConfigAsync(tenantId);
        if (tenantConfig == null)
            return principal;

        var identity = principal.Identity as ClaimsIdentity;
        if (identity == null)
            return principal;

        var transformedClaims = new List<Claim>();

        // Add tenant_id claim
        transformedClaims.Add(new Claim("tenant_id", tenantId));

        // Apply claim mappings from tenant configuration
        foreach (var mapping in tenantConfig.ClaimMappings)
        {
            var sourceClaim = identity.FindFirst(mapping.SourceClaim);

            if (sourceClaim != null)
            {
                transformedClaims.Add(new Claim(mapping.TargetClaim, sourceClaim.Value));
            }
            else if (!string.IsNullOrEmpty(mapping.DefaultValue))
            {
                transformedClaims.Add(new Claim(mapping.TargetClaim, mapping.DefaultValue));
            }
        }

        // Transform common B2C claims
        TransformB2CClaims(identity, transformedClaims);

        // Add transformed claims to identity
        identity.AddClaims(transformedClaims);

        return principal;
    }

    private static void TransformB2CClaims(ClaimsIdentity identity, List<Claim> transformedClaims)
    {
        // Map B2C 'oid' (object ID) to 'sub' if not present
        var oid = identity.FindFirst("oid") ?? identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier");
        if (oid != null && identity.FindFirst(ClaimTypes.NameIdentifier) == null)
        {
            transformedClaims.Add(new Claim(ClaimTypes.NameIdentifier, oid.Value));
        }

        // Map B2C email claims
        var email = identity.FindFirst("emails") ?? 
                    identity.FindFirst("email") ?? 
                    identity.FindFirst(ClaimTypes.Email);
        if (email != null)
        {
            // B2C 'emails' claim may be JSON array, take first
            var emailValue = email.Value.TrimStart('[').TrimEnd(']').Trim('"');
            if (!string.IsNullOrEmpty(emailValue))
            {
                transformedClaims.Add(new Claim("email", emailValue));
            }
        }

        // Map display name
        var name = identity.FindFirst("name") ?? 
                   identity.FindFirst(ClaimTypes.Name) ??
                   identity.FindFirst("displayName");
        if (name != null)
        {
            transformedClaims.Add(new Claim("name", name.Value));
        }

        // Map given name and family name
        var givenName = identity.FindFirst(ClaimTypes.GivenName) ?? identity.FindFirst("given_name");
        var familyName = identity.FindFirst(ClaimTypes.Surname) ?? identity.FindFirst("family_name");

        if (givenName != null)
            transformedClaims.Add(new Claim("given_name", givenName.Value));
        if (familyName != null)
            transformedClaims.Add(new Claim("family_name", familyName.Value));
    }
}
