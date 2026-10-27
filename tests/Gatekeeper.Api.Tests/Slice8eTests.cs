using System.Reflection;
using Gatekeeper.Api;

namespace Gatekeeper.Api.Tests;

/// <summary>Slice 8e: `prune-audit` arguments and the refusals that need no database.</summary>
public class Slice8eTests
{
    [Fact]
    public void Valid_arguments_are_parsed()
    {
        var o = PruneAudit.Parse(["--older-than", "365", "--export", "/tmp/a.jsonl"], out var error);
        Assert.Null(error);
        Assert.Equal(new PruneAudit.Options(365, "/tmp/a.jsonl", false), o);
        Assert.Equal(new PruneAudit.Options(30, null, true), PruneAudit.Parse(["--dry-run", "--older-than", "30"], out _));
    }

    [Theory]
    [InlineData]
    [InlineData("--older-than")]
    [InlineData("--older-than", "abc")]
    [InlineData("--older-than", "-5")]
    [InlineData("--older-than", "+40")]
    [InlineData("--older-than", "1e3")]
    [InlineData("--older-than", "99999999999")]
    [InlineData("--older-than", "36501")]
    [InlineData("--older-than", "0")]
    [InlineData("--older-than", "29")]
    [InlineData("--older-than", "30", "--older-than", "40")]
    [InlineData("--older-than", "30", "--export")]
    [InlineData("--older-than", "30", "--export", "")]
    [InlineData("--older-than", "30", "--export", "a", "--export", "b")]
    [InlineData("--older-than", "30", "--dry-run", "--export", "a")]
    [InlineData("--older-than", "30", "--dry-run", "--dry-run")]
    [InlineData("--older-than", "30", "--force")]
    [InlineData("--older-than", "30", "extra")]
    [InlineData("--older-than=30")]
    public void Bad_arguments_are_refused_with_a_message(params string[] args)
    {
        Assert.Null(PruneAudit.Parse(args, out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void The_minimum_is_30_days_and_the_message_says_so()
    {
        Assert.Null(PruneAudit.Parse(["--older-than", "29"], out var error));
        Assert.Contains("at least 30", error);
        Assert.NotNull(PruneAudit.Parse(["--older-than", "30"], out _));
    }

    [Fact]
    public void An_export_path_too_long_for_the_trace_row_is_refused()
    {
        Assert.Null(PruneAudit.Parse(["--older-than", "30", "--export", new string('a', 101)], out _));
    }

    [Fact]
    public void A_value_that_looks_like_an_option_is_refused_for_every_option_value()
    {
        Assert.Null(PruneAudit.Parse(["--older-than", "30", "--export", "--dry-run"], out var error));
        Assert.Contains("needs a value", error);
        Assert.Null(PruneAudit.Parse(["--older-than", "--dry-run"], out _));
        Assert.Null(PruneAudit.Parse(["--export", "--older-than", "30"], out _));
    }

    [Fact]
    public void Allow_large_is_a_flag_and_only_once()
    {
        Assert.True(PruneAudit.Parse(["--older-than", "30", "--allow-large"], out _)!.AllowLarge);
        Assert.False(PruneAudit.Parse(["--older-than", "30"], out _)!.AllowLarge);
        Assert.Null(PruneAudit.Parse(["--older-than", "30", "--allow-large", "--allow-large"], out _));
    }

    [Theory]
    [InlineData("a b.jsonl")]
    [InlineData("a\nb.jsonl")]
    [InlineData("a\tb.jsonl")]
    [InlineData("a\u0007b.jsonl")]
    [InlineData("a\"b.jsonl")]
    [InlineData("a\\b.jsonl")]
    [InlineData("/tmp/dir/")]
    [InlineData(" /tmp/x.jsonl")]
    public void Export_paths_with_whitespace_control_characters_or_quotes_are_refused(string path)
        => Assert.Null(PruneAudit.Parse(["--older-than", "30", "--export", path], out _));

    [Fact]
    public void A_relative_export_path_is_made_absolute_and_the_length_is_judged_on_the_absolute_form()
    {
        var o = PruneAudit.Parse(["--older-than", "30", "--export", "out.jsonl"], out _);
        Assert.Equal(Path.GetFullPath("out.jsonl"), o!.Export);
        // short as typed, too long once resolved
        Assert.Null(PruneAudit.Parse(["--older-than", "30", "--export", "/" + new string('a', 100)], out _));
        Assert.NotNull(PruneAudit.Parse(["--older-than", "30", "--export", "/" + new string('a', 99)], out _));
    }

    private static async Task<(int Code, string Err)> RunMain(params string[] args)
    {
        var main = typeof(Program).Assembly.EntryPoint!;
        var oldErr = Console.Error;
        using var err = new StringWriter();
        Console.SetError(err);
        try
        {
            var result = main.Invoke(null, [args])!;
            return (result is Task<int> task ? await task : (int)result, err.ToString());
        }
        finally { Console.SetError(oldErr); }
    }

    [Fact]
    public async Task The_command_exits_non_zero_on_bad_arguments_and_on_the_in_memory_store()
    {
        var (code, err) = await RunMain("prune-audit");
        Assert.Equal(1, code);
        Assert.Contains("--older-than is required", err);
        (code, err) = await RunMain("prune-audit", "--older-than", "5");
        Assert.Equal(1, code);
        Assert.Contains("at least 30", err);
        (code, err) = await RunMain("prune-audit", "--older-than", "365");
        Assert.Equal(1, code);
        Assert.Contains("InMemory", err);
    }
}
