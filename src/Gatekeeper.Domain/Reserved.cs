namespace Gatekeeper.Domain;

/// <summary>Names Gatekeeper itself relies on. The management API is guarded by the admin role of the admin app.</summary>
public static class Reserved
{
    public const string AdminApp = "gatekeeper";
    public const string AdminRole = "admin";

    /// <summary>True if the name is the admin role, ignoring case (older data may hold "ADMIN"). The policy itself matches exactly.</summary>
    public static bool IsAdminRole(string? name) => string.Equals(name, AdminRole, StringComparison.OrdinalIgnoreCase);
}
