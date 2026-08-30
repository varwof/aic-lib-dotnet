namespace Varwof.Aic;

/// <summary>A matching rule with an action (Go types.CapabilityRule), used for
/// "deny overrides allow" decisions.</summary>
public sealed record CapabilityRule(string Pattern, bool Deny)
{
    public static CapabilityRule Allow(string pattern) => new(pattern, false);
    public static CapabilityRule DenyRule(string pattern) => new(pattern, true);
}