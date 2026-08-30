namespace Varwof.Aic;

/// <summary>Result of matching a capability ID against a rule set
/// (Go types.CapabilityRuleMatch).</summary>
public sealed class CapabilityRuleMatch
{
    public bool Matched { get; }
    public bool Deny { get; }
    public int Priority { get; }
    public string Pattern { get; }

    public static readonly CapabilityRuleMatch NoMatch = new(false, false, MatchPriority.NoMatch, "");

    public CapabilityRuleMatch(bool matched, bool deny, int priority, string pattern)
    {
        Matched = matched;
        Deny = deny;
        Priority = priority;
        Pattern = pattern ?? throw new System.ArgumentNullException(nameof(pattern));
    }

    public override string ToString()
    {
        if (!Matched)
        {
            return "no-match";
        }
        return (Deny ? "deny(" : "allow(") + Pattern + ", " + MatchPriority.Name(Priority) + ")";
    }
}