using Gatekeeper.Domain;

namespace Gatekeeper.Domain.Tests;

public class ValidationTests
{
    [Theory]
    [InlineData("billing")]
    [InlineData("a")]
    [InlineData("my-app_2.0")]
    public void AppName_accepts_slugs(string name) => Validation.AppName(name);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("Has Space")]
    [InlineData("UPPER")]
    [InlineData("-leading")]
    public void AppName_rejects_invalid(string? name) =>
        Assert.Contains("name", Assert.Throws<ValidationException>(() => Validation.AppName(name)).Errors.Keys);

    [Theory]
    [InlineData("admin\n")]
    [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    [InlineData("3f2504e04f8911d39a0c0305e82c3301")]
    public void Slug_rejects_trailing_newline_and_guid_lookalikes(string name) =>
        Assert.Throws<ValidationException>(() => Validation.AppName(name));

    [Theory]
    [InlineData("a\0b")]
    [InlineData("a\u001bb")]
    [InlineData("a\r\nb")]
    [InlineData("a\u202eb")]
    [InlineData("\0")]
    public void Free_text_rejects_control_characters_and_invalid_unicode(string text)
    {
        Assert.Contains("displayName",
            Assert.Throws<ValidationException>(() => Validation.UserFields("alice", "a@b.co", text)).Errors.Keys);
        Assert.Contains("description",
            Assert.Throws<ValidationException>(() => Validation.RoleFields("admin", text)).Errors.Keys);
    }

    [Fact]
    public void Free_text_rejects_lone_surrogates()
    {
        // Built at runtime: xunit would replace a lone surrogate in InlineData with U+FFFD.
        var text = "a" + (char)0xD800 + "b";
        Assert.Contains("displayName",
            Assert.Throws<ValidationException>(() => Validation.UserFields("alice", "a@b.co", text)).Errors.Keys);
        Assert.True(Validation.IsCleanText("a😀b"));
        Assert.False(Validation.IsCleanText("a\ude00b"));
    }

    [Theory]
    [InlineData("emoji 😀🎉 日本語 ñ")]
    [InlineData("")]
    [InlineData("  padded  ")]
    public void Free_text_accepts_normal_unicode(string text) =>
        Validation.UserFields("alice", "a@b.co", text);

    [Theory]
    [InlineData("émile@example.com")]
    [InlineData("a@exämple.com")]
    [InlineData("a b@example.com")]
    [InlineData("a@b")]
    [InlineData("a@@b.co")]
    [InlineData("a\0@b.co")]
    public void Email_rejects_non_ascii_and_malformed(string email) =>
        Assert.Contains("email", Assert.Throws<ValidationException>(() => Validation.UserFields("alice", email, null)).Errors.Keys);

    [Theory]
    [InlineData("alice@example.com")]
    [InlineData("A.B+tag@Sub.Example.COM")]
    public void Email_accepts_ascii(string email) => Validation.UserFields("alice", email, null);

    [Fact]
    public void Email_rejects_trailing_newline() =>
        Assert.Contains("email",
            Assert.Throws<ValidationException>(() => Validation.UserFields("alice", "a@b.co\n", null)).Errors.Keys);

    [Fact]
    public void AppName_rejects_too_long() =>
        Assert.Throws<ValidationException>(() => Validation.AppName(new string('a', 65)));

    [Fact]
    public void UserFields_collects_all_errors()
    {
        var ex = Assert.Throws<ValidationException>(() => Validation.UserFields("Bad Name", "nope", null));
        Assert.Equal(["email", "username"], ex.Errors.Keys.Order());
    }

    [Fact]
    public void UserFields_accepts_valid_with_empty_display_name() =>
        Validation.UserFields("alice", "alice@example.com", null);

    [Fact]
    public void RoleFields_rejects_overlong_description() =>
        Assert.Contains("description",
            Assert.Throws<ValidationException>(() => Validation.RoleFields("admin", new string('x', 257))).Errors.Keys);
}

public class UserLifetimeTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_test_user_needs_an_expiry_within_a_year() => Validation.UserLifetime(UserKind.Test, Now.AddDays(30), Now);

    [Theory]
    [InlineData(null)]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(366)]
    public void A_test_user_without_a_valid_expiry_is_refused(int? days) =>
        Assert.Contains("expiresAt", Assert.Throws<ValidationException>(() =>
            Validation.UserLifetime(UserKind.Test, days is null ? null : Now.AddDays(days.Value), Now)).Errors.Keys);

    [Fact]
    public void The_limit_is_inclusive_at_a_year() => Validation.UserLifetime(UserKind.Test, Now.AddDays(365), Now);

    [Fact]
    public void An_unchanged_expiry_is_accepted_even_if_it_has_passed_or_is_far_ahead()
    {
        var old = Now.AddDays(-3);
        Validation.UserLifetime(UserKind.Test, old, Now, current: old);
        Assert.Throws<ValidationException>(() => Validation.UserLifetime(UserKind.Test, old, Now));
    }

    [Theory]
    [InlineData(UserKind.Person)]
    [InlineData(UserKind.Shared)]
    public void Only_test_users_may_have_an_expiry(UserKind kind)
    {
        Validation.UserLifetime(kind, null, Now);
        Assert.Contains("expiresAt", Assert.Throws<ValidationException>(() => Validation.UserLifetime(kind, Now.AddDays(1), Now)).Errors.Keys);
    }

    [Fact]
    public void An_undefined_kind_is_refused() =>
        Assert.Contains("kind", Assert.Throws<ValidationException>(() => Validation.UserLifetime((UserKind)99, null, Now)).Errors.Keys);

    [Fact]
    public void A_user_is_usable_until_it_is_disabled_or_expired()
    {
        var u = new User(Guid.NewGuid(), "t", "t@example.com", "", true, Now, Now, UserKind.Test, Now.AddDays(1));
        Assert.True(u.IsUsable(Now));
        Assert.False(u.IsUsable(Now.AddDays(1)));            // the expiry instant itself is already too late
        Assert.False((u with { IsActive = false }).IsUsable(Now));
        Assert.True((u with { Kind = UserKind.Person, ExpiresAt = null }).IsUsable(Now.AddYears(10)));
    }
}
