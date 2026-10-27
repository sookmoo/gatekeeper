using Gatekeeper.Api;

namespace Gatekeeper.Api.Tests;

/// <summary>Independent QA for slice 8e argument handling.</summary>
public class Qa8eTests
{
    [Fact]
    public void Leading_zeros_are_accepted_as_the_same_number()
        => Assert.Equal(40, PruneAudit.Parse(["--older-than", "0040"], out _)?.Days);

    [Fact]
    public void Boundaries_30_and_36500_are_accepted()
    {
        Assert.NotNull(PruneAudit.Parse(["--older-than", "30"], out _));
        Assert.NotNull(PruneAudit.Parse(["--older-than", "36500"], out _));
        Assert.Null(PruneAudit.Parse(["--older-than", "36501"], out _));
    }

    [Theory]
    [InlineData(" 40")]
    [InlineData("40 ")]
    [InlineData("4 0")]
    [InlineData("4_0")]
    [InlineData("٤٠")] // arabic-indic digits
    [InlineData("40.0")]
    [InlineData("")]
    public void Non_ascii_digit_or_padded_numbers_are_refused(string value)
        => Assert.Null(PruneAudit.Parse(["--older-than", value], out _));

    [Fact]
    public void A_flag_is_not_swallowed_as_the_export_file_name()
    {
        // `--export --dry-run` would make a file called "--dry-run" and silently run for real. Expected: refused.
        var o = PruneAudit.Parse(["--older-than", "30", "--export", "--dry-run"], out _);
        Assert.Null(o);
    }

    [Fact]
    public void A_flag_is_not_swallowed_as_the_older_than_value()
        => Assert.Null(PruneAudit.Parse(["--older-than", "--dry-run"], out _));
}
