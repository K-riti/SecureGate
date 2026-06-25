using Microsoft.EntityFrameworkCore;
using SecureGate.Core.Auth;
using SecureGate.Core.Tenancy;

namespace SecureGate.Infrastructure.Persistence;

/// <summary>
/// Entity Framework Core DbContext for SecureGate.
/// </summary>
public class SecureGateDbContext : DbContext
{
    public SecureGateDbContext(DbContextOptions<SecureGateDbContext> options) : base(options)
    {
    }

    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<TenantEntity> Tenants => Set<TenantEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<AuthorizationCodeEntity> AuthorizationCodes => Set<AuthorizationCodeEntity>();
    public DbSet<ClientEntity> Clients => Set<ClientEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User configuration
        modelBuilder.Entity<UserEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.TenantId, e.Email }).IsUnique();
            entity.Property(e => e.PasswordHash).HasMaxLength(500);
        });

        // Tenant configuration
        modelBuilder.Entity<TenantEntity>(entity =>
        {
            entity.HasKey(e => e.TenantId);
            entity.HasIndex(e => e.Domain).IsUnique();
        });

        // Refresh token configuration
        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.HasKey(e => e.Token);
            entity.HasIndex(e => e.FamilyId);
            entity.HasIndex(e => new { e.UserId, e.TenantId });
        });

        // Authorization code configuration
        modelBuilder.Entity<AuthorizationCodeEntity>(entity =>
        {
            entity.HasKey(e => e.Code);
            entity.HasIndex(e => e.ExpiresAt);
        });

        // Client configuration
        modelBuilder.Entity<ClientEntity>(entity =>
        {
            entity.HasKey(e => new { e.TenantId, e.ClientId });
        });
    }
}

// Entity classes
public class UserEntity
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string TenantId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? PasswordHash { get; set; }
    public string? DisplayName { get; set; }
    public List<string> Roles { get; set; } = new();
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public string? ExternalId { get; set; } // For federated users (B2C)
}

public class TenantEntity
{
    public string TenantId { get; set; } = string.Empty;
    public string TenantName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public string? ConfigJson { get; set; } // Serialized TenantConfig
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class RefreshTokenEntity
{
    public string Token { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public string? ClientId { get; set; }
    public string FamilyId { get; set; } = string.Empty;
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? PreviousToken { get; set; }
}

public class AuthorizationCodeEntity
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

public class ClientEntity
{
    public string TenantId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string? ClientSecretHash { get; set; }
    public bool IsPublicClient { get; set; } = true;
    public string AllowedGrantTypesJson { get; set; } = "[]";
    public string AllowedScopesJson { get; set; } = "[]";
    public string AllowedRedirectUrisJson { get; set; } = "[]";
    public bool IsActive { get; set; } = true;
}

/// <summary>
/// EF Core implementation of IRefreshTokenStore.
/// </summary>
public class EfRefreshTokenStore : IRefreshTokenStore
{
    private readonly SecureGateDbContext _context;

    public EfRefreshTokenStore(SecureGateDbContext context)
    {
        _context = context;
    }

    public async Task StoreAsync(RefreshToken token)
    {
        var entity = new RefreshTokenEntity
        {
            Token = token.Token,
            UserId = token.UserId,
            TenantId = token.TenantId,
            ClientId = token.ClientId,
            FamilyId = token.FamilyId,
            IssuedAt = token.IssuedAt,
            ExpiresAt = token.ExpiresAt,
            IsRevoked = token.IsRevoked,
            RevokedAt = token.RevokedAt,
            PreviousToken = token.PreviousToken
        };

        _context.RefreshTokens.Add(entity);
        await _context.SaveChangesAsync();
    }

    public async Task<RefreshToken?> GetAsync(string token)
    {
        var entity = await _context.RefreshTokens.FindAsync(token);
        if (entity == null) return null;

        return new RefreshToken
        {
            Token = entity.Token,
            UserId = entity.UserId,
            TenantId = entity.TenantId,
            ClientId = entity.ClientId,
            FamilyId = entity.FamilyId,
            IssuedAt = entity.IssuedAt,
            ExpiresAt = entity.ExpiresAt,
            IsRevoked = entity.IsRevoked,
            RevokedAt = entity.RevokedAt,
            PreviousToken = entity.PreviousToken
        };
    }

    public async Task UpdateAsync(RefreshToken token)
    {
        var entity = await _context.RefreshTokens.FindAsync(token.Token);
        if (entity != null)
        {
            entity.IsRevoked = token.IsRevoked;
            entity.RevokedAt = token.RevokedAt;
            await _context.SaveChangesAsync();
        }
    }

    public async Task RevokeFamilyAsync(string familyId)
    {
        var tokens = await _context.RefreshTokens
            .Where(t => t.FamilyId == familyId && !t.IsRevoked)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
    }
}
