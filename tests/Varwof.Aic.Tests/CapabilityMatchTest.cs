using System.Collections.Generic;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>
/// Capability matching; vector-for-vector port of Go match_priority_test.go
/// and matchcap_test.go (and the Java CapabilityMatchTest).
/// </summary>
public class CapabilityMatchTest
{
    [Fact]
    public void MatchCapabilityPriorityLevels()
    {
        var cases = new (string Id, string Pat, int Want)[]
        {
            ("database:query:SELECT", "database:query:SELECT", MatchPriority.Exact),
            ("database:query:SELECT", "database:query:*", MatchPriority.Single),
            ("database:query:SELECT", "database:*:SELECT", MatchPriority.Single),
            ("database:query:EXPLAIN", "database:*:SELECT", MatchPriority.NoMatch),
            ("database:query:SELECT", "database:**", MatchPriority.Multi),
            ("database:query:SELECT", "**", MatchPriority.Global),
            ("database:query:SELECT", "database:**:SELECT", MatchPriority.Multi),
            ("database:query:EXPLAIN", "database:**:SELECT", MatchPriority.NoMatch),
            ("mysql:query:SELECT", "*:query:SELECT", MatchPriority.Scheme),
            ("pgsql:query:SELECT", "*:query:SELECT", MatchPriority.Scheme),
            ("mysql:query:EXPLAIN", "*:query:SELECT", MatchPriority.NoMatch),
            ("anything:at:all", "*", MatchPriority.Global),
            ("anything:at:all", "**", MatchPriority.Global),
            ("anything:at:all", "*:*", MatchPriority.Global),
        };
        foreach ((string id, string pat, int want) in cases)
        {
            Assert.Equal(want, CapabilityMatcher.MatchCapabilityPriority(id, pat));
        }
    }

    [Fact]
    public void ExactBeatsGlobalDeny()
    {
        string id = "database:query:SELECT";
        var rules = new List<CapabilityRule>
        {
            new("**", true),
            new("database:query:*", true),
            new("database:query:SELECT", false),
        };
        CapabilityRuleMatch m = CapabilityMatcher.MatchCapabilityRules(id, rules);
        Assert.True(m.Matched);
        Assert.False(m.Deny);
        Assert.Equal(MatchPriority.Exact, m.Priority);
        Assert.Equal("database:query:SELECT", m.Pattern);
    }

    [Fact]
    public void DenyOverridesAllowAtSamePriority()
    {
        string id = "database:query:SELECT";
        var rules = new List<CapabilityRule>
        {
            new("database:**", true),
            new("database:query:SELECT", false),
        };
        CapabilityRuleMatch m = CapabilityMatcher.MatchCapabilityRules(id, rules);
        Assert.True(m.Matched);
        Assert.False(m.Deny);

        var rules2 = new List<CapabilityRule>
        {
            new("database:query:SELECT", false),
            new("database:query:SELECT", true),
        };
        CapabilityRuleMatch m2 = CapabilityMatcher.MatchCapabilityRules(id, rules2);
        Assert.True(m2.Matched);
        Assert.True(m2.Deny);
    }

    [Fact]
    public void NoMatchWhenNoRuleMatches()
    {
        CapabilityRuleMatch m = CapabilityMatcher.MatchCapabilityRules("ca:create",
            new List<CapabilityRule> { new("crl:*", false) });
        Assert.False(m.Matched);
    }

    [Fact]
    public void MatchCapabilityCompatibility()
    {
        var compat = new (string Id, string Pat)[]
        {
            ("gateway:admin", "gateway:admin"),
            ("gateway:admin", "gateway:*"),
            ("ca:issuing:create", "ca:**"),
            ("anything", "**"),
            ("anything", "*"),
        };
        foreach ((string id, string pat) in compat)
        {
            Assert.True(CapabilityMatcher.MatchCapability(id, pat));
            Assert.True(CapabilityMatcher.MatchCapabilityPriority(id, pat) > MatchPriority.NoMatch);
        }
        Assert.False(CapabilityMatcher.MatchCapability("ca:create", "crl:*"));
    }

    [Fact]
    public void MatchCapabilityExact()
    {
        Assert.True(CapabilityMatcher.MatchCapability("gateway:admin", "gateway:admin"));
        Assert.True(CapabilityMatcher.MatchCapability("anything", "**"));
        Assert.True(CapabilityMatcher.MatchCapability("anything", "*"));
        Assert.True(CapabilityMatcher.MatchCapability("ca:list", "ca:*"));
        Assert.True(CapabilityMatcher.MatchCapability("ca:create", "ca:*"));
        Assert.True(CapabilityMatcher.MatchCapability("gateway:admin", "gateway:?dmin"));
        Assert.True(CapabilityMatcher.MatchCapability("ca:issuing:create", "ca:**"));
        Assert.False(CapabilityMatcher.MatchCapability("ca:create", "crl:*"));
        Assert.False(CapabilityMatcher.MatchCapability("gateway:admin", "gateway:ops"));
    }

    [Fact]
    public void MatchDoubleStarSemantics()
    {
        Assert.True(CapabilityMatcher.MatchCapability("ca:issuing:create", "ca:**"));
        Assert.True(CapabilityMatcher.MatchCapability("a/b:c", "a/**"));
        Assert.False(CapabilityMatcher.MatchCapability("ca:create", "crl:**"));
    }
}
