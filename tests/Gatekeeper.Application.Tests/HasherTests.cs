using Gatekeeper.Domain;
using Gatekeeper.Infrastructure;

namespace Gatekeeper.Application.Tests;

public class HasherTests
{
    // Small parameters keep the suite fast; production defaults are covered by NeedsRehash below.
    private readonly Argon2PasswordHasher _h = new(new Argon2Options(MemoryKiB: 64, Iterations: 1, Parallelism: 1));

    [Fact]
    public void Roundtrip_and_wrong_password()
    {
        var hash = _h.Hash("correct horse battery");
        Assert.StartsWith("$argon2id$v=19$m=64,t=1,p=1$", hash);
        Assert.True(_h.Verify(hash, "correct horse battery"));
        Assert.False(_h.Verify(hash, "correct horse batterY"));
    }

    [Fact]
    public void Salts_differ_per_hash() =>
        Assert.NotEqual(_h.Hash("same password 123"), _h.Hash("same password 123"));

    [Fact]
    public void Non_ascii_passwords_work_and_are_not_normalised()
    {
        var hash = _h.Hash("p\u00e4ssword-long-enough");
        Assert.True(_h.Verify(hash, "p\u00e4ssword-long-enough"));
        Assert.False(_h.Verify(hash, "pa\u0308ssword-long-enough")); // documented: no normalisation
    }

    [Theory]
    [InlineData("")]
    [InlineData("plaintext")]
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$AAAA$AAAA")]                       // salt/hash too short
    [InlineData("$argon2id$v=19$m=99999999,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // absurd memory
    [InlineData("$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Malformed_stored_values_never_verify_or_throw(string stored)
    {
        Assert.False(_h.Verify(stored, "anything at all"));
        Assert.True(_h.NeedsRehash(stored));
    }

    [Fact]
    public void NeedsRehash_detects_parameter_changes()
    {
        var weak = _h.Hash("some long password");
        Assert.False(_h.NeedsRehash(weak));
        Assert.True(new Argon2PasswordHasher().NeedsRehash(weak));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("short")]
    [InlineData("has a\u0000nul in it ok")]
    public void Password_policy_rejects(string? password) =>
        Assert.Contains("password", Assert.Throws<ValidationException>(() => Validation.Password(password)).Errors.Keys);

    [Fact]
    public void Password_policy_bounds()
    {
        Validation.Password(new string('a', 12));
        Validation.Password(new string('a', 128));
        Assert.Throws<ValidationException>(() => Validation.Password(new string('a', 129)));
        Validation.Password("spaces and \u00fcmlauts are fine");
    }
}
