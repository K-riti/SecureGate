# SecureGate Architecture

> Technical architecture documentation for the SecureGate Identity & Access Management microservice.

## Table of Contents

1. [Overview](#overview)
2. [System Components](#system-components)
3. [Authentication Flows](#authentication-flows)
4. [Multi-Tenancy](#multi-tenancy)
5. [Security Considerations](#security-considerations)
6. [Data Model](#data-model)
7. [API Reference](#api-reference)

---

## Overview

SecureGate is a production-grade OAuth 2.0 / OpenID Connect identity service built with ASP.NET Core 8. It provides centralized authentication and authorization for multi-tenant applications.

### Design Principles

- **Security First**: All sensitive operations follow OWASP guidelines
- **Multi-Tenant Isolation**: Complete data separation between tenants
- **Standards Compliance**: RFC 6749, RFC 7636, RFC 7662, RFC 7009
- **Extensibility**: Plugin-based architecture for custom IdP integrations

---

## System Components

### Core Layer (`SecureGate.Core`)

| Component | Responsibility |
|-----------|----------------|
| `PkceValidator` | Validates PKCE code challenges (S256 method) |
| `JwtIssuer` | Issues RS256-signed JWT access and ID tokens |
| `RefreshTokenRotator` | Manages sliding-window token rotation |
| `ClaimsTransformer` | Transforms IdP claims to application claims |
| `CredentialHasher` | PBKDF2-SHA256 password hashing |
| `TenantConfigService` | Per-tenant OAuth/OIDC configuration |

### API Layer (`SecureGate.API`)

| Endpoint | Purpose |
|----------|---------|
| `GET /oauth/authorize` | OAuth 2.0 Authorization endpoint |
| `POST /oauth/token` | Token exchange endpoint |
| `POST /oauth/introspect` | Token introspection (RFC 7662) |
| `POST /oauth/revoke` | Token revocation (RFC 7009) |
| `GET /oauth/userinfo` | OIDC UserInfo endpoint |
| `GET /.well-known/openid-configuration` | OIDC Discovery |

### Infrastructure Layer (`SecureGate.Infrastructure`)

| Component | Responsibility |
|-----------|----------------|
| `SecureGateDbContext` | EF Core data access |
| `KeyVaultService` | Azure Key Vault key management |
| `B2CClaimsTransformer` | Azure AD B2C claims mapping |

---

## Authentication Flows

### Authorization Code Flow with PKCE

```
┌──────────┐                              ┌──────────────┐                              ┌─────────────┐
│  Client  │                              │  SecureGate  │                              │  Azure B2C  │
└────┬─────┘                              └──────┬───────┘                              └──────┬──────┘
	 │                                           │                                             │
	 │ 1. Generate code_verifier                 │                                             │
	 │    code_challenge = SHA256(verifier)      │                                             │
	 │                                           │                                             │
	 │ 2. GET /authorize?                        │                                             │
	 │    response_type=code&                    │                                             │
	 │    code_challenge=...&                    │                                             │
	 │    code_challenge_method=S256             │                                             │
	 │ ─────────────────────────────────────────>│                                             │
	 │                                           │                                             │
	 │                                           │ 3. Redirect to B2C                          │
	 │                                           │ ───────────────────────────────────────────>│
	 │                                           │                                             │
	 │                                           │                          4. User logs in   │
	 │                                           │                                             │
	 │                                           │ 5. Return id_token + code                   │
	 │                                           │ <───────────────────────────────────────────│
	 │                                           │                                             │
	 │ 6. Redirect with auth_code                │                                             │
	 │ <─────────────────────────────────────────│                                             │
	 │                                           │                                             │
	 │ 7. POST /token                            │                                             │
	 │    grant_type=authorization_code&         │                                             │
	 │    code=...&code_verifier=...             │                                             │
	 │ ─────────────────────────────────────────>│                                             │
	 │                                           │                                             │
	 │                                           │ 8. Verify PKCE:                             │
	 │                                           │    SHA256(verifier) == challenge            │
	 │                                           │                                             │
	 │ 9. Return tokens                          │                                             │
	 │    {access_token, refresh_token, id_token}│                                             │
	 │ <─────────────────────────────────────────│                                             │
	 │                                           │                                             │
```

### Refresh Token Rotation

```
┌──────────┐                              ┌──────────────┐
│  Client  │                              │  SecureGate  │
└────┬─────┘                              └──────┬───────┘
	 │                                           │
	 │ POST /token                               │
	 │   grant_type=refresh_token&               │
	 │   refresh_token=RT_v1                     │
	 │ ─────────────────────────────────────────>│
	 │                                           │
	 │                                           │ 1. Validate RT_v1
	 │                                           │ 2. Mark RT_v1 as used
	 │                                           │ 3. Issue new RT_v2 (same family)
	 │                                           │ 4. Issue new access_token
	 │                                           │
	 │ {access_token, refresh_token: RT_v2}      │
	 │ <─────────────────────────────────────────│
	 │                                           │
	 │ ═══════════════════════════════════════════
	 │ REPLAY ATTACK DETECTED (RT_v1 reused)
	 │ ═══════════════════════════════════════════
	 │                                           │
	 │ POST /token                               │
	 │   refresh_token=RT_v1 (already used!)     │
	 │ ─────────────────────────────────────────>│
	 │                                           │
	 │                                           │ REVOKE ENTIRE TOKEN FAMILY
	 │                                           │ (RT_v1, RT_v2, all descendants)
	 │                                           │
	 │ 401 Unauthorized                          │
	 │ <─────────────────────────────────────────│
```

---

## Multi-Tenancy

### Tenant Resolution

Tenants are resolved in the following priority order:

1. `X-Tenant-ID` header
2. `tenant_id` query parameter
3. Subdomain (e.g., `tenant1.securegate.com`)
4. Route parameter

### Tenant Isolation

```
┌─────────────────────────────────────────────────────────────┐
│                      SecureGate                             │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │    Tenant A     │  │    Tenant B     │  │  Tenant C   │ │
│  │                 │  │                 │  │             │ │
│  │ • RSA Keys      │  │ • RSA Keys      │  │ • RSA Keys  │ │
│  │ • Users         │  │ • Users         │  │ • Users     │ │
│  │ • Clients       │  │ • Clients       │  │ • Clients   │ │
│  │ • Tokens        │  │ • Tokens        │  │ • Tokens    │ │
│  │ • Config        │  │ • Config        │  │ • Config    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│                                                             │
│  ✗ No cross-tenant queries                                  │
│  ✗ No shared signing keys                                   │
│  ✓ tenant_id claim in every JWT                             │
│  ✓ Validated on every API request                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### Token Security

| Measure | Implementation |
|---------|----------------|
| Signing Algorithm | RS256 (asymmetric) |
| Key Storage | Azure Key Vault |
| Access Token TTL | 15 minutes |
| Refresh Token TTL | 30 days (sliding) |
| PKCE | Required for public clients |

### Password Security

| Measure | Implementation |
|---------|----------------|
| Algorithm | PBKDF2-SHA256 |
| Iterations | 100,000 |
| Salt | 16 bytes per user |
| Hash Size | 32 bytes |

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Token Replay | Refresh token family revocation |
| CSRF | State parameter + PKCE |
| Token Leakage | Short-lived access tokens |
| Brute Force | Rate limiting (planned) |

---

## Data Model

```
┌─────────────────┐     ┌─────────────────┐
│     Tenant      │     │      User       │
├─────────────────┤     ├─────────────────┤
│ TenantId (PK)   │────<│ Id (PK)         │
│ TenantName      │     │ TenantId (FK)   │
│ Domain          │     │ Email           │
│ IsEnabled       │     │ PasswordHash    │
│ ConfigJson      │     │ Roles[]         │
└─────────────────┘     │ IsActive        │
						└─────────────────┘
							   │
							   │
┌─────────────────┐     ┌──────▼──────────┐
│     Client      │     │  RefreshToken   │
├─────────────────┤     ├─────────────────┤
│ TenantId (PK)   │     │ Token (PK)      │
│ ClientId (PK)   │     │ UserId          │
│ ClientName      │     │ TenantId        │
│ SecretHash      │     │ FamilyId        │
│ IsPublicClient  │     │ ExpiresAt       │
│ RedirectUris[]  │     │ IsRevoked       │
└─────────────────┘     └─────────────────┘
```

---

## API Reference

### Authorization Endpoint

```http
GET /oauth/authorize
	?response_type=code
	&client_id={client_id}
	&redirect_uri={redirect_uri}
	&scope=openid profile email
	&state={state}
	&code_challenge={code_challenge}
	&code_challenge_method=S256
```

### Token Endpoint

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={authorization_code}
&redirect_uri={redirect_uri}
&client_id={client_id}
&code_verifier={code_verifier}
```

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile email"
}
```

### Introspection Endpoint

```http
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded

token={access_token}
```

### Introspection Response

```json
{
  "active": true,
  "sub": "user-123",
  "client_id": "demo-spa",
  "tenant_id": "demo",
  "scope": "openid profile email",
  "exp": 1719350400,
  "iat": 1719349500,
  "iss": "https://securegate.local",
  "token_type": "Bearer"
}
```

---

## Deployment

### Docker

```bash
docker-compose up -d
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ConnectionStrings__DefaultConnection` | SQL Server connection string |
| `Jwt__Issuer` | Token issuer URL |
| `Jwt__Audience` | Token audience |
| `KeyVault__Uri` | Azure Key Vault URI |
| `AzureAdB2C__Instance` | B2C tenant URL |

---

## References

- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7009 - Token Revocation](https://tools.ietf.org/html/rfc7009)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
