using Gatekeeper.Domain;

namespace Gatekeeper.Application.Tests;

public class PagingTests
{
    [Fact]
    public void Defaults_apply_when_nothing_is_given()
    {
        var q = PageQuery.Parse(null, null);
        Assert.Equal(new PageQuery(0, PageQuery.DefaultLimit), q);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(PageQuery.MaxLimit + 1)]
    public void Limit_out_of_range_is_rejected(int limit) =>
        Assert.Contains("limit", Assert.Throws<ValidationException>(() => PageQuery.Parse(limit, null)).Errors.Keys);

    [Theory]
    [InlineData("")]
    [InlineData("not a cursor")]
    [InlineData("b-1")]
    [InlineData("bzE=")]   // "o1" with padding: not the canonical form
    public void Garbage_cursors_are_rejected(string cursor) =>
        Assert.Contains("cursor", Assert.Throws<ValidationException>(() => PageQuery.Parse(null, cursor)).Errors.Keys);

    [Fact]
    public void Build_trims_the_extra_row_and_issues_a_cursor_that_roundtrips()
    {
        var q = PageQuery.Parse(2, null);
        var first = q.Build<int>([1, 2, 3]);
        Assert.Equal([1, 2], first.Items);
        Assert.NotNull(first.NextCursor);
        var next = PageQuery.Parse(2, first.NextCursor);
        Assert.Equal(2, next.Offset);
        var last = next.Build<int>([3]);
        Assert.Equal([3], last.Items);
        Assert.Null(last.NextCursor);
    }

    [Fact]
    public void Exactly_a_full_page_has_no_next_cursor() =>
        Assert.Null(PageQuery.Parse(2, null).Build<int>([1, 2]).NextCursor);

    [Fact]
    public void Absurd_offsets_are_rejected()
    {
        var cursor = Convert.ToBase64String("o999999999"u8.ToArray()).TrimEnd('=');
        Assert.Throws<ValidationException>(() => PageQuery.Parse(null, cursor));
    }
}
