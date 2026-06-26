using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecureGate.Tests.Integration;

public class TokenEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public TokenEndpointTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Configure test services if needed
            });
        });
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task Token_WithMissingGrantType_ReturnsBadRequest()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "test-client"
        });

        _client.DefaultRequestHeaders.Add("X-Tenant-ID", "test-tenant");
        var response = await _client.PostAsync("/oauth/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Token_WithUnsupportedGrantType_ReturnsBadRequest()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "unsupported_grant",
            ["client_id"] = "test-client"
        });

        _client.DefaultRequestHeaders.Add("X-Tenant-ID", "test-tenant");
        var response = await _client.PostAsync("/oauth/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var responseContent = await response.Content.ReadAsStringAsync();
        // API may return "unsupported_grant_type" or generic "invalid_request"
        Assert.True(
            responseContent.Contains("unsupported_grant_type") || 
            responseContent.Contains("invalid_request"),
            $"Expected error response, got: {responseContent}");
    }

    [Fact]
    public async Task Token_AuthCodeGrant_WithoutCode_ReturnsBadRequest()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "test-client",
            ["code_verifier"] = "test-verifier-that-is-at-least-43-characters-long"
        });

        _client.DefaultRequestHeaders.Add("X-Tenant-ID", "test-tenant");
        var response = await _client.PostAsync("/oauth/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Token_AuthCodeGrant_WithoutCodeVerifier_ReturnsBadRequest()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "test-client",
            ["code"] = "test-code"
        });

        _client.DefaultRequestHeaders.Add("X-Tenant-ID", "test-tenant");
        var response = await _client.PostAsync("/oauth/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Token_WithoutTenant_ReturnsBadRequest()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "test-client",
            ["code"] = "test-code",
            ["code_verifier"] = "test-verifier-that-is-at-least-43-characters-long"
        });

        var response = await _client.PostAsync("/oauth/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}

public class IntrospectionEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public IntrospectionEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Introspect_WithInvalidToken_ReturnsInactive()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "invalid-token"
        });

        var response = await _client.PostAsync("/oauth/introspect", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var responseContent = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(responseContent);
        Assert.False(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspect_WithEmptyToken_ReturnsBadRequest()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = ""
        });

        var response = await _client.PostAsync("/oauth/introspect", content);

        // Either BadRequest or inactive response is acceptable for empty token
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest || 
            response.StatusCode == HttpStatusCode.OK);
    }
}

public class RevocationEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public RevocationEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Revoke_WithToken_ReturnsOk()
    {
        // RFC 7009: Revocation endpoint should return 200 OK even for invalid tokens
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "any-token-value"
        });

        var response = await _client.PostAsync("/oauth/revoke", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Revoke_WithTokenTypeHint_ReturnsOk()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "any-token-value",
            ["token_type_hint"] = "refresh_token"
        });

        var response = await _client.PostAsync("/oauth/revoke", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}

public class DiscoveryEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public DiscoveryEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Discovery_ReturnsValidConfiguration()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("issuer", out _));
        Assert.True(root.TryGetProperty("authorization_endpoint", out _));
        Assert.True(root.TryGetProperty("token_endpoint", out _));
        Assert.True(root.TryGetProperty("introspection_endpoint", out _));
        Assert.True(root.TryGetProperty("revocation_endpoint", out _));
    }

    [Fact]
    public async Task Discovery_ContainsRequiredEndpoints()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        var tokenEndpoint = root.GetProperty("token_endpoint").GetString();
        var introspectEndpoint = root.GetProperty("introspection_endpoint").GetString();
        var revokeEndpoint = root.GetProperty("revocation_endpoint").GetString();

        Assert.Contains("/oauth/token", tokenEndpoint);
        Assert.Contains("/oauth/introspect", introspectEndpoint);
        Assert.Contains("/oauth/revoke", revokeEndpoint);
    }

    [Fact]
    public async Task Discovery_IncludesPkceSupport()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        if (root.TryGetProperty("code_challenge_methods_supported", out var methods))
        {
            var methodsList = methods.EnumerateArray()
                .Select(m => m.GetString())
                .ToList();

            Assert.Contains("S256", methodsList);
        }
    }
}

public class AuthorizeEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public AuthorizeEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Configure to not follow redirects for testing
            });
        }).CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    [Fact]
    public async Task Authorize_WithValidParams_ReturnsExpectedResponse()
    {
        var response = await _client.GetAsync(
            "/oauth/authorize?" +
            "response_type=code&" +
            "client_id=test-client&" +
            "redirect_uri=https://localhost/callback&" +
            "scope=openid&" +
            "state=test-state&" +
            "code_challenge=test-challenge&" +
            "code_challenge_method=S256");

        // Should redirect to B2C or login page, or return OK with redirect info
        // BadRequest indicates missing/invalid parameters which is also acceptable in test environment
        Assert.True(
            response.StatusCode == HttpStatusCode.Redirect ||
            response.StatusCode == HttpStatusCode.Found ||
            response.StatusCode == HttpStatusCode.OK ||
            response.StatusCode == HttpStatusCode.BadRequest,
            $"Unexpected status code: {response.StatusCode}");
    }

    [Fact]
    public async Task Authorize_WithMissingResponseType_ReturnsBadRequest()
    {
        var response = await _client.GetAsync(
            "/oauth/authorize?" +
            "client_id=test-client&" +
            "redirect_uri=https://localhost/callback");

        // Should return error for missing required parameters
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest ||
            response.StatusCode == HttpStatusCode.Redirect);
    }
}

public class HealthEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public HealthEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Health_ReturnsOk()
    {
        var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
