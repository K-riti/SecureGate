using SecureGate.Core.Tenancy;

namespace SecureGate.API.Middleware;

/// <summary>
/// Resolves the current tenant from the request and makes it available via HttpContext.
/// </summary>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;
    public const string TenantIdKey = "TenantId";
    public const string TenantConfigKey = "TenantConfig";

    public TenantResolutionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, TenantConfigService tenantService)
    {
        var tenantId = ResolveTenantId(context);

        if (!string.IsNullOrEmpty(tenantId))
        {
            var tenantConfig = await tenantService.GetConfigAsync(tenantId);

            if (tenantConfig != null && tenantConfig.IsEnabled)
            {
                context.Items[TenantIdKey] = tenantId;
                context.Items[TenantConfigKey] = tenantConfig;
            }
        }

        await _next(context);
    }

    private static string? ResolveTenantId(HttpContext context)
    {
        // 1. Check X-Tenant-ID header
        if (context.Request.Headers.TryGetValue("X-Tenant-ID", out var headerTenant))
            return headerTenant.FirstOrDefault();

        // 2. Check query parameter
        if (context.Request.Query.TryGetValue("tenant_id", out var queryTenant))
            return queryTenant.FirstOrDefault();

        // 3. Check subdomain (e.g., tenant1.securegate.com)
        var host = context.Request.Host.Host;
        var parts = host.Split('.');
        if (parts.Length >= 3)
            return parts[0];

        // 4. Check route value
        if (context.Request.RouteValues.TryGetValue("tenantId", out var routeTenant))
            return routeTenant?.ToString();

        return null;
    }
}

public static class TenantResolutionMiddlewareExtensions
{
    public static IApplicationBuilder UseTenantResolution(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<TenantResolutionMiddleware>();
    }
}

public static class HttpContextTenantExtensions
{
    public static string? GetTenantId(this HttpContext context)
    {
        return context.Items.TryGetValue(TenantResolutionMiddleware.TenantIdKey, out var tenantId)
            ? tenantId as string
            : null;
    }

    public static TenantConfig? GetTenantConfig(this HttpContext context)
    {
        return context.Items.TryGetValue(TenantResolutionMiddleware.TenantConfigKey, out var config)
            ? config as TenantConfig
            : null;
    }
}
