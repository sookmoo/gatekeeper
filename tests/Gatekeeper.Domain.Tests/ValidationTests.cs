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
