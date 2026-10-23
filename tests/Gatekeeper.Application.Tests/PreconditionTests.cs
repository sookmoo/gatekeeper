using Gatekeeper.Application;
using Gatekeeper.Domain;

namespace Gatekeeper.Application.Tests;

/// <summary>Slice 6d: parsing and matching of If-Match.</summary>
public class PreconditionTests
{
    [Theory]
    [InlineData("\"3\"", 3, true)]
    [InlineData("\"3\"", 4, false)]
    [InlineData("  \"3\"  ", 3, true)]
    [InlineData("\"2\",\"3\"", 3, true)]
    [InlineData("\"2\" , \"3\"", 2, true)]
    [InlineData("\"2\", \"3\"", 4, false)]
    [InlineData("W/\"3\"", 3, false)]            // weak tags never match
    [InlineData("W/\"3\", \"4\"", 4, true)]      // a strong tag next to a weak one still matches
    [InlineData("W/\"3\", W/\"4\"", 4, false)]
    [InlineData("\"03\"", 3, false)]             // the tag is the canonical decimal text
    [InlineData("\"+3\"", 3, false)]
    [InlineData("\"\"", 1, false)]               // an empty tag is well-formed and matches nothing
    [InlineData("\"a,b\"", 1, false)]            // a comma inside a tag is not a separator
    [InlineData("\"3\",", 3, true)]               // empty list elements are ignored
    [InlineData(",\"3\"", 3, true)]
    [InlineData("\"2\",, \"3\" ,", 3, true)]
    [InlineData("*", 7, true)]
    [InlineData(" * ", 7, true)]
    public void Well_formed_headers_match_by_strong_comparison(string header, long version, bool matches) =>
        Assert.Equal(matches, Precondition.Parse(header).Matches(version));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("3")]
    [InlineData("abc")]
    [InlineData("\"3")]
    [InlineData("3\"")]
    [InlineData("W/")]
    [InlineData("W/3")]
    [InlineData("w/\"3\"")]
    [InlineData("\"3\" \"4\"")]
    [InlineData("*, \"3\"")]
    [InlineData("\"3\", *")]
    [InlineData(",")]
    [InlineData(" , , ")]
    [InlineData("**")]
    [InlineData("\"a\"b\"")]
    [InlineData("\"a b\"")]
    [InlineData("'3'")]
    [InlineData("\"3\"\n")]
    public void Malformed_headers_are_a_validation_error(string header)
    {
        var ex = Assert.Throws<ValidationException>(() => Precondition.Parse(header));
        Assert.Contains("If-Match", ex.Errors.Keys);
    }

    [Fact]
    public void A_header_over_the_length_limit_is_malformed()
    {
        Assert.Throws<ValidationException>(() => Precondition.Parse("\"" + new string('1', 1100) + "\""));
        Precondition.Parse("\"" + new string('1', 1000) + "\""); // within the limit
    }

    [Fact]
    public void Require_returns_the_version_the_store_must_still_find()
    {
        Assert.Null(Precondition.Require(null, 5));                                   // no precondition: unconditional
        Assert.Null(Precondition.Require(Precondition.Parse("*"), 5));                // any existing row
        Assert.Equal(5, Precondition.Require(Precondition.Parse("\"4\", \"5\""), 5));
        Assert.Throws<PreconditionFailedException>(() => Precondition.Require(Precondition.Parse("\"4\""), 5));
        Assert.Throws<PreconditionFailedException>(() => Precondition.Require(Precondition.Parse("W/\"5\""), 5));
    }

    [Theory]
    [InlineData(" , ")]
    [InlineData(",")]
    [InlineData(" ")]
    [InlineData("\t,")]
    [InlineData("\"a\" ,")]
    public void Adversarial_inputs_of_the_maximum_length_parse_in_linear_time(string unit)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        foreach (var tail in new[] { "x", "", ",x", "\"", "W/" })
        {
            var evil = "\"1\"" + string.Concat(Enumerable.Repeat(unit, 1024 / unit.Length - 4)) + tail;
            evil = evil[..Math.Min(evil.Length, 1024)];
            try { Precondition.Parse(evil); } catch (ValidationException) { }
        }
        Assert.True(sw.Elapsed < TimeSpan.FromMilliseconds(500), $"took {sw.Elapsed}");
    }
}
