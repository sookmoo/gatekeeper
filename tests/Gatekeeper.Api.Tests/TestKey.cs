using System.Security.Cryptography;

namespace Gatekeeper.Api.Tests;

internal static class TestKey
{
    /// <summary>A throwaway P-256 key generated per test run (never a committed secret).</summary>
    public static readonly string Pem = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportPkcs8PrivateKeyPem();
}
