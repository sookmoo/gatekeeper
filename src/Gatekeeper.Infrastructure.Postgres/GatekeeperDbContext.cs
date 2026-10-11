using Gatekeeper.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Gatekeeper.Infrastructure.Postgres;

/// <summary>Persistence-only join row; the domain models assignments as a repository operation.</summary>
internal sealed record UserRoleRow(Guid UserId, Guid RoleId);

public sealed class GatekeeperDbContext(DbContextOptions<GatekeeperDbContext> options) : DbContext(options)
{
    public DbSet<App> Apps => Set<App>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<User> Users => Set<User>();
    internal DbSet<UserRoleRow> UserRoles => Set<UserRoleRow>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        // citext gives case-insensitive equality and unique indexes, matching the in-memory store.
        b.HasPostgresExtension("citext");

        b.Entity<App>(e =>
        {
            e.ToTable("apps");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasColumnType("citext").IsRequired();
            e.HasIndex(x => x.Name).IsUnique().HasDatabaseName(Names.AppNameIndex);
        });

        b.Entity<Role>(e =>
        {
            e.ToTable("roles");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasColumnType("citext").IsRequired();
            e.Property(x => x.Description).IsRequired();
            e.HasOne<App>().WithMany().HasForeignKey(x => x.AppId)
                .OnDelete(DeleteBehavior.Cascade).HasConstraintName(Names.RoleAppFk);
            e.HasIndex(x => new { x.AppId, x.Name }).IsUnique().HasDatabaseName(Names.RoleNameIndex);
        });

        b.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Username).HasColumnType("citext").IsRequired();
            e.Property(x => x.Email).HasColumnType("citext").IsRequired();
            e.Property(x => x.DisplayName).IsRequired();
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
    public const string AssignmentRoleFk = "fk_user_roles_roles";
}
