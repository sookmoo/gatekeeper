using System.Security.Cryptography;
using System.Text;
using Gatekeeper.Application;
using Konscious.Security.Cryptography;

namespace Gatekeeper.Infrastructure;

/// <summary>
/// Argon2id password hashing, stored as a PHC string ($argon2id$v=19$m=..,t=..,p=..$salt$hash).
/// Passwords are hashed as their UTF-8 bytes exactly as typed. Unicode normalisation is deliberately not applied:
/// the app runs with InvariantGlobalization (no ICU), where string.Normalize silently does nothing.
/// </summary>
public sealed class Argon2PasswordHasher(Argon2Options? options = null) : IPasswordHasher
{
    private readonly Argon2Options _o = options ?? new Argon2Options();
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Compute(password, salt, _o.MemoryKiB, _o.Iterations, _o.Parallelism, HashBytes);
        return $"$argon2id$v=19$m={_o.MemoryKiB},t={_o.Iterations},p={_o.Parallelism}${B64(salt)}${B64(hash)}";
    }

    public bool Verify(string hash, string password)
    {
        if (!TryParse(hash, out var m, out var t, out var p, out var salt, out var expected)) return false;
        var actual = Compute(password, salt, m, t, p, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public bool NeedsRehash(string hash) =>
        !TryParse(hash, out var m, out var t, out var p, out _, out var h)
        || m != _o.MemoryKiB || t != _o.Iterations || p != _o.Parallelism || h.Length != HashBytes;

    private static byte[] Compute(string password, byte[] salt, int m, int t, int p, int length)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon = new Argon2id(bytes) { Salt = salt, MemorySize = m, Iterations = t, DegreeOfParallelism = p };
            return argon.GetBytes(length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    // Bounds stop a tampered or corrupt stored value from making a login attempt exhaust memory or CPU.
    private static bool TryParse(string phc, out int m, out int t, out int p, out byte[] salt, out byte[] hash)
    {
        (m, t, p, salt, hash) = (0, 0, 0, [], []);
        var parts = phc.Split('$');
        if (parts.Length != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19") return false;
        var kv = parts[3].Split(',');
        if (kv.Length != 3 || !kv[0].StartsWith("m=") || !kv[1].StartsWith("t=") || !kv[2].StartsWith("p=")) return false;
        if (!int.TryParse(kv[0][2..], out m) || !int.TryParse(kv[1][2..], out t) || !int.TryParse(kv[2][2..], out p)) return false;
        if (m is < 8 or > 262_144 || t is < 1 or > 10 || p is < 1 or > 8) return false;
        try
        {
            salt = Convert.FromBase64String(Pad(parts[4]));
            hash = Convert.FromBase64String(Pad(parts[5]));
        }
        catch (FormatException)
        {
            return false;
        }
        return salt.Length is >= 8 and <= 64 && hash.Length is >= 16 and <= 64;
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=');
    private static string Pad(string s) => s + new string('=', (4 - s.Length % 4) % 4);
}

/// <summary>OWASP-recommended minimum for Argon2id: 19 MiB, 2 iterations; the defaults here are stronger.</summary>
public sealed record Argon2Options(int MemoryKiB = 65_536, int Iterations = 3, int Parallelism = 1);
