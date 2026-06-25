using Microsoft.AspNetCore.Antiforgery;

namespace SecureGate.API.Middleware;

/// <summary>
/// CSRF protection middleware for token endpoints.
/// Validates anti-forgery tokens on state-changing requests.
/// </summary>
public class CsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAntiforgery _antiforgery;

    private static readonly HashSet<string> ProtectedMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "POST", "PUT", "DELETE", "PATCH"
    };

    private static readonly HashSet<string> ExcludedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/oauth/token",      // Token endpoint uses PKCE for protection
        "/oauth/introspect", // Protected by client authentication
        "/oauth/revoke"      // Protected by token ownership
    };

    public CsrfProtectionMiddleware(RequestDelegate next, IAntiforgery antiforgery)
    {
        _next = next;
        _antiforgery = antiforgery;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var method = context.Request.Method;

        // Skip CSRF validation for excluded paths and safe methods
        if (!ProtectedMethods.Contains(method) || IsExcludedPath(path))
        {
            await _next(context);
            return;
        }

        // Skip if request has valid Authorization header (API requests)
        if (context.Request.Headers.ContainsKey("Authorization"))
        {
            await _next(context);
            return;
        }

        // Validate CSRF token for browser-based requests
        try
        {
            await _antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "invalid_request",
                error_description = "CSRF validation failed"
            });
            return;
        }

        await _next(context);
    }

    private static bool IsExcludedPath(string path)
    {
        return ExcludedPaths.Any(excluded => 
            path.StartsWith(excluded, StringComparison.OrdinalIgnoreCase));
    }
}

public static class CsrfProtectionMiddlewareExtensions
{
    public static IApplicationBuilder UseCsrfProtection(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CsrfProtectionMiddleware>();
    }
}
