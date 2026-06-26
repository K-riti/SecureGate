using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SecureGate.API.Controllers;
using SecureGate.API.Middleware;
using SecureGate.Core.Auth;
using SecureGate.Core.Tenancy;

var builder = WebApplication.CreateBuilder(args); 

// Add controllers
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure JWT Settings
var jwtSettings = builder.Configuration.GetSection("Jwt").Get<JwtSettings>() ?? new JwtSettings
{
    Issuer = "https://securegate.local",
    Audience = "securegate-api",
    KeyId = "default-key",
    AccessTokenLifetimeMinutes = 15,
    IdTokenLifetimeMinutes = 60
};
builder.Services.AddSingleton(jwtSettings);

// Configure RSA key for JWT signing
var rsa = RSA.Create(2048);
builder.Services.AddSingleton(rsa);

// Add JWT Bearer Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new RsaSecurityKey(rsa),
        ClockSkew = TimeSpan.FromMinutes(1)
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("admin"));
    options.AddPolicy("User", policy => policy.RequireRole("user", "admin"));
});

// Configure Swagger with JWT support
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SecureGate API", Version = "v1" });

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Register Core Services
builder.Services.AddSingleton<PkceValidator>();
builder.Services.AddSingleton<JwtIssuer>(sp =>
{
    var settings = sp.GetRequiredService<JwtSettings>();
    var rsaKey = sp.GetRequiredService<RSA>();
    return new JwtIssuer(settings, rsaKey);
});

builder.Services.AddSingleton(new RefreshTokenSettings { LifetimeDays = 30 });
builder.Services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
builder.Services.AddSingleton<RefreshTokenRotator>();

// Register Tenant Services
builder.Services.AddSingleton<ITenantConfigStore, InMemoryTenantConfigStore>();
builder.Services.AddScoped<TenantConfigService>();

// Register Authorization Code Store
builder.Services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();

var app = builder.Build();

// Seed demo tenant configuration
await SeedDemoTenantAsync(app.Services);

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add tenant resolution middleware
app.UseTenantResolution();

// Add authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

// OIDC Discovery endpoint
app.MapGet("/.well-known/openid-configuration", (HttpContext context) =>
{
    var tenantId = context.GetTenantId() ?? "default";
    var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";

    return Results.Ok(new
    {
        issuer = jwtSettings.Issuer,
        authorization_endpoint = $"{baseUrl}/oauth/authorize",
        token_endpoint = $"{baseUrl}/oauth/token",
        introspection_endpoint = $"{baseUrl}/oauth/introspect",
        revocation_endpoint = $"{baseUrl}/oauth/revoke",
        jwks_uri = $"{baseUrl}/.well-known/jwks.json",
        response_types_supported = new[] { "code" },
        grant_types_supported = new[] { "authorization_code", "refresh_token" },
        code_challenge_methods_supported = new[] { "S256" },
        token_endpoint_auth_methods_supported = new[] { "none", "client_secret_post" },
        scopes_supported = new[] { "openid", "profile", "email" },
        claims_supported = new[] { "sub", "tenant_id", "email", "name", "roles" }
    });
});

app.Run();

// Seed demo data
static async Task SeedDemoTenantAsync(IServiceProvider services)
{
    var tenantStore = services.GetRequiredService<ITenantConfigStore>();

    var demoTenant = new TenantConfig
    {
        TenantId = "demo",
        TenantName = "Demo Tenant",
        Domain = "demo.securegate.local",
        IsEnabled = true,
        AllowedRedirectUris = new List<string>
        {
            "http://localhost:3000/callback",
            "https://localhost:5001/callback"
        },
        RegisteredClients = new List<RegisteredClient>
        {
            new RegisteredClient
            {
                ClientId = "demo-spa",
                ClientName = "Demo SPA Application",
                IsPublicClient = true,
                AllowedGrantTypes = new List<string> { "authorization_code" },
                AllowedScopes = new List<string> { "openid", "profile", "email" }
            }
        }
    };

    await tenantStore.SaveAsync(demoTenant);
}

// In-memory implementations for development
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly Dictionary<string, RefreshToken> _tokens = new();

    public Task StoreAsync(RefreshToken token)
    {
        _tokens[token.Token] = token;
        return Task.CompletedTask;
    }

    public Task<RefreshToken?> GetAsync(string token)
    {
        _tokens.TryGetValue(token, out var refreshToken);
        return Task.FromResult(refreshToken);
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
}

public class InMemoryTenantConfigStore : ITenantConfigStore
{
    private readonly Dictionary<string, TenantConfig> _tenants = new();

    public Task<TenantConfig?> GetByIdAsync(string tenantId)
    {
        _tenants.TryGetValue(tenantId, out var config);
        return Task.FromResult(config);
    }

    public Task<TenantConfig?> GetByDomainAsync(string domain)
    {
        var config = _tenants.Values.FirstOrDefault(t => 
            t.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(config);
    }

    public Task<IEnumerable<TenantConfig>> GetAllAsync()
    {
        return Task.FromResult<IEnumerable<TenantConfig>>(_tenants.Values);
    }

    public Task SaveAsync(TenantConfig config)
    {
        _tenants[config.TenantId] = config;
        return Task.CompletedTask;
    }
}

public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly Dictionary<string, AuthorizationRequest> _requests = new();
    private readonly Dictionary<string, AuthorizationCode> _codes = new();

    public Task StoreRequestAsync(AuthorizationRequest request)
    {
        _requests[request.RequestId] = request;
        return Task.CompletedTask;
    }

    public Task<AuthorizationRequest?> GetRequestAsync(string requestId)
    {
        _requests.TryGetValue(requestId, out var request);
        return Task.FromResult(request);
    }

    public Task StoreCodeAsync(AuthorizationCode code)
    {
        _codes[code.Code] = code;
        return Task.CompletedTask;
    }

    public Task<AuthorizationCode?> GetCodeAsync(string code)
    {
        _codes.TryGetValue(code, out var authCode);
        return Task.FromResult(authCode);
    }

    public Task MarkCodeUsedAsync(string code)
    {
        if (_codes.TryGetValue(code, out var authCode))
        {
            authCode.IsUsed = true;
        }
        return Task.CompletedTask;
    }
}

// Make Program accessible for integration tests
public partial class Program { }
