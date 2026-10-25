using Gatekeeper.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Gatekeeper.Infrastructure.Postgres;

/// <summary>Persistence-only join row; the domain models assignments as a repository operation.</summary>
internal sealed record UserRoleRow(Guid UserId, Guid RoleId);

/// <summary>Session columns including the token hashes (the domain record deliberately has no hashes).</summary>
internal sealed class SessionRow
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid AppId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastUsedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset AuthenticatedAt { get; set; }
    public string TokenHash { get; set; } = "";
    public string? PreviousTokenHash { get; set; }

    public Session ToDomain() => new(Id, UserId, AppId, CreatedAt, LastUsedAt, ExpiresAt, RevokedAt, AuthenticatedAt);
}

internal sealed record ClientSecretRow(Guid ClientId, string Hash, DateTimeOffset UpdatedAt);

internal sealed record ClientRoleRow(Guid ClientId, Guid RoleId);

/// <summary>Password hash for a user; one row per user, removed with the user.</summary>
internal sealed record UserCredentialRow(Guid UserId, string Hash, DateTimeOffset UpdatedAt);

public sealed class GatekeeperDbContext(DbContextOptions<GatekeeperDbContext> options) : DbContext(options)
{
    public DbSet<App> Apps => Set<App>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<User> Users => Set<User>();
    internal DbSet<UserRoleRow> UserRoles => Set<UserRoleRow>();
    internal DbSet<UserCredentialRow> Credentials => Set<UserCredentialRow>();
    public DbSet<Client> Clients => Set<Client>();
    internal DbSet<ClientSecretRow> ClientSecrets => Set<ClientSecretRow>();
    internal DbSet<ClientRoleRow> ClientRoles => Set<ClientRoleRow>();
    internal DbSet<SessionRow> Sessions => Set<SessionRow>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        // citext gives case-insensitive equality and unique indexes, matching the in-memory store.
        b.HasPostgresExtension("citext");

        b.Entity<App>(e =>
        {
            e.ToTable("apps");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasColumnType("citext").IsRequired();
            e.Property(x => x.Version).IsConcurrencyToken().HasDefaultValue(1L);
            e.HasIndex(x => x.Name).IsUnique().HasDatabaseName(Names.AppNameIndex);
        });

        b.Entity<Role>(e =>
        {
            e.ToTable("roles");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasColumnType("citext").IsRequired();
            e.Property(x => x.Description).IsRequired();
            e.Property(x => x.Version).IsConcurrencyToken().HasDefaultValue(1L);
            e.HasOne<App>().WithMany().HasForeignKey(x => x.AppId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.RoleAppFk);
            e.HasIndex(x => new { x.AppId, x.Name }).IsUnique().HasDatabaseName(Names.RoleNameIndex);
        });

        b.Entity<User>(e =>
        {
            e.ToTable("users", t =>
            {
                t.HasCheckConstraint("ck_users_kind", "kind IN ('person', 'test', 'shared')");
                t.HasCheckConstraint("ck_users_test_expires", "(kind = 'test') = (expires_at IS NOT NULL)"); // only test users expire, and they always do
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.Username).HasColumnType("citext").IsRequired();
            e.Property(x => x.Email).HasColumnType("citext").IsRequired();
            e.Property(x => x.DisplayName).IsRequired();
            e.Property(x => x.Version).IsConcurrencyToken().HasDefaultValue(1L);
            e.Property(x => x.Kind).HasConversion(k => k.ToString().ToLowerInvariant(), v => Enum.Parse<UserKind>(v, true))
                .HasMaxLength(16).HasDefaultValue(UserKind.Person).IsRequired();
            e.HasIndex(x => x.Username).IsUnique().HasDatabaseName(Names.UsernameIndex);
            e.HasIndex(x => x.Email).IsUnique().HasDatabaseName(Names.EmailIndex);
        });

        b.Entity<UserRoleRow>(e =>
        {
            e.ToTable("user_roles");
            e.HasKey(x => new { x.UserId, x.RoleId });
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.AssignmentUserFk);
            e.HasOne<Role>().WithMany().HasForeignKey(x => x.RoleId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.AssignmentRoleFk);
        });

        b.Entity<UserCredentialRow>(e =>
        {
            e.ToTable("user_credentials");
            e.HasKey(x => x.UserId);
            e.Property(x => x.Hash).IsRequired();
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.CredentialUserFk);
        });

        b.Entity<Client>(e =>
        {
            e.ToTable("clients");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasColumnType("citext").IsRequired();
            e.Property(x => x.Version).IsConcurrencyToken().HasDefaultValue(1L);
            e.HasOne<App>().WithMany().HasForeignKey(x => x.AppId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.ClientAppFk);
            e.HasIndex(x => x.Name).IsUnique().HasDatabaseName(Names.ClientNameIndex);
        });

        b.Entity<ClientSecretRow>(e =>
        {
            e.ToTable("client_secrets");
            e.HasKey(x => x.ClientId);
            e.Property(x => x.Hash).IsRequired();
            e.HasOne<Client>().WithMany().HasForeignKey(x => x.ClientId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.ClientSecretFk);
        });

        b.Entity<ClientRoleRow>(e =>
        {
            e.ToTable("client_roles");
            e.HasKey(x => new { x.ClientId, x.RoleId });
            e.HasOne<Client>().WithMany().HasForeignKey(x => x.ClientId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.ClientRoleClientFk);
            e.HasOne<Role>().WithMany().HasForeignKey(x => x.RoleId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.ClientRoleRoleFk);
        });

        b.Entity<SessionRow>(e =>
        {
            e.ToTable("sessions");
            e.HasKey(x => x.Id);
            e.Property(x => x.TokenHash).IsRequired();
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.SessionUserFk);
            e.HasOne<App>().WithMany().HasForeignKey(x => x.AppId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.SessionAppFk);
            e.HasIndex(x => new { x.UserId, x.CreatedAt }).HasDatabaseName("ix_sessions_user_id_created_at");
            e.HasIndex(x => x.ExpiresAt).HasDatabaseName("ix_sessions_expires_at");
        });

        b.Entity<AuditEvent>(e =>
        {
            e.ToTable("audit_events");
            e.HasKey(x => x.Id);
            e.Property(x => x.Actor).IsRequired();
            e.Property(x => x.Action).IsRequired();
            e.Property(x => x.Outcome).IsRequired();
            e.HasIndex(x => new { x.At, x.Id }).HasDatabaseName("ix_audit_events_at_id");
            e.HasIndex(x => new { x.Actor, x.At, x.Id }).HasDatabaseName("ix_audit_events_actor_at_id").IsDescending(false, true, true);
            e.HasIndex(x => new { x.Action, x.At, x.Id }).HasDatabaseName("ix_audit_events_action_at_id").IsDescending(false, true, true);
        });

        foreach (var property in b.Model.GetEntityTypes().SelectMany(t => t.GetProperties()))
            property.SetColumnName(SnakeCase(property.Name));
    }

    private static string SnakeCase(string name) =>
        string.Concat(name.Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
}

/// <summary>Constraint names, shared by the model and the error translation.</summary>
internal static class Names
{
    public const string AppNameIndex = "ix_apps_name";
    public const string RoleNameIndex = "ix_roles_app_id_name";
    public const string UsernameIndex = "ix_users_username";
    public const string EmailIndex = "ix_users_email";
    public const string RoleAppFk = "fk_roles_apps";
    public const string AssignmentUserFk = "fk_user_roles_users";
    public const string CredentialUserFk = "fk_user_credentials_users";
    public const string AssignmentRoleFk = "fk_user_roles_roles";
    public const string SessionUserFk = "fk_sessions_users";
    public const string SessionAppFk = "fk_sessions_apps";
    public const string ClientNameIndex = "ix_clients_name";
    public const string ClientAppFk = "fk_clients_apps";
    public const string ClientSecretFk = "fk_client_secrets_clients";
    public const string ClientRoleClientFk = "fk_client_roles_clients";
    public const string ClientRoleRoleFk = "fk_client_roles_roles";
}
