namespace Varwof.Aic;

/// <summary>
/// Priority levels for capabilityId matching (Go types/match_priority.go).
/// Higher values are more specific; the highest-priority matching rule wins,
/// and at equal priority deny overrides allow.
/// </summary>
public static class MatchPriority
{
    public const int NoMatch = 0;
    public const int Global = 1;
    public const int Scheme = 2;
    public const int Multi = 3;
    public const int Single = 4;
    public const int Exact = 5;

    public static string Name(int p) => p switch
    {
        NoMatch => "no-match",
        Global => "global",
        Scheme => "scheme",
        Multi => "multi",
        Single => "single",
        Exact => "exact",
        _ => "unknown(" + p + ")"
    };

    /// <summary>Semantic ordering for deny-overrides-allow decisions: higher beats lower.</summary>
    public static int Rank(int p) => p;
}