using Gatekeeper.Domain;

namespace Gatekeeper.Domain.Tests;

/// <summary>Slice 7a: when a sign-in still counts after a user's session cut-off.</summary>
public class CutOffTests
{
    private static readonly DateTimeOffset Cut = new(2026, 10, 25, 12, 0, 0, 500, TimeSpan.Zero); // half a second into the second
    private static User UserWith(DateTimeOffset? cut) =>
        new(Guid.NewGuid(), "u", "u@example.com", "", true, Cut, Cut, SessionsValidAfter: cut);

    [Fact]
    public void Without_a_cut_off_everything_counts()
    {
        var u = UserWith(null);
        Assert.True(u.CountsAfterCutOff(DateTimeOffset.MinValue));
        Assert.True(u.TokenCountsAfterCutOff(null));
        Assert.True(u.TokenCountsAfterCutOff(0));
    }

    [Fact]
    public void A_sign_in_counts_only_when_strictly_after_the_cut_off()
    {
        var u = UserWith(Cut);
        Assert.False(u.CountsAfterCutOff(Cut.AddTicks(-10)));
        Assert.False(u.CountsAfterCutOff(Cut)); // a tie is conservative
        Assert.True(u.CountsAfterCutOff(Cut.AddTicks(10)));
    }

    [Fact]
    public void A_token_without_a_session_counts_only_from_the_next_whole_second()
    {
        var u = UserWith(Cut);
        var second = Cut.ToUnixTimeSeconds();
        Assert.False(u.TokenCountsAfterCutOff(second - 5));
        Assert.False(u.TokenCountsAfterCutOff(second));     // same second as the cut-off: sign in again
        Assert.True(u.TokenCountsAfterCutOff(second + 1));
    }

    [Fact]
    public void A_token_with_neither_auth_time_nor_iat_fails_closed_once_a_cut_off_exists()
    {
        Assert.False(UserWith(Cut).TokenCountsAfterCutOff(null));
        Assert.True(UserWith(null).TokenCountsAfterCutOff(null));
    }

    [Fact]
    public void A_session_stamp_defaults_to_its_creation_time()
    {
        var created = Cut.AddHours(-1);
        var s = new Session(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), created, created, created.AddDays(1), null);
        Assert.Equal(created, s.Stamp);
        Assert.Equal(Cut, (s with { AuthenticatedAt = Cut }).Stamp);
    }

    [Fact]
    public void The_cut_off_is_not_part_of_the_user_json()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(UserWith(Cut));
        Assert.DoesNotContain("essions", json);
        var session = System.Text.Json.JsonSerializer.Serialize(new Session(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Cut, Cut, Cut, null, Cut));
        Assert.DoesNotContain("uthenticated", session);
        Assert.DoesNotContain("tamp", session);
    }
}
