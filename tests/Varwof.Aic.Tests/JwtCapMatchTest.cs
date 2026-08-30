using System.Collections.Generic;
using System.Text.Json.Nodes;
using Varwof.Aic.Jwt;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>Ports Go types/aicjwt/capmatch_test.go (CapabilitySubset) plus the
/// pattern/precedence rules of draft Section 6.2.</summary>
public class JwtCapMatchTest
{
    private static Claims.Capability Cap(string scheme, string id)
        => new() { Scheme = scheme, Id = id };

    private static Claims.Capability Cap(string scheme, string id, string paramsJson)
        => new() { Scheme = scheme, Id = id, Params = JwtJson.Parse(paramsJson) };

    [Fact]
    public void CapabilitySubset()
    {
        var queryStar = new List<Claims.Capability> { Cap("database", "query:*") };
        var querySelect = new List<Claims.Capability> { Cap("database", "query:SELECT") };

        Assert.True(CapMatch.CapabilitySubset(Cap("database", "query:SELECT"), querySelect));
        Assert.True(CapMatch.CapabilitySubset(Cap("database", "query:SELECT"), queryStar));
        Assert.False(CapMatch.CapabilitySubset(Cap("database", "query:*"), querySelect));
        Assert.False(CapMatch.CapabilitySubset(Cap("database", "query:SELECT"),
            new List<Claims.Capability> { Cap("http", "query:*") }));
        Assert.True(CapMatch.CapabilitySubset(Cap("database", "query:SELECT", "{\"max_rows\":500}"),
            new List<Claims.Capability> { Cap("database", "query:*", "{\"max_rows\":1000}") }));
        Assert.False(CapMatch.CapabilitySubset(Cap("database", "query:SELECT", "{\"max_rows\":2000}"),
            new List<Claims.Capability> { Cap("database", "query:*", "{\"max_rows\":1000}") }));
        Assert.True(CapMatch.CapabilitySubset(Cap("database", "query:SELECT", "{\"max_rows\":100}"),
            new List<Claims.Capability> { Cap("database", "query:*") }));
        Assert.False(CapMatch.CapabilitySubset(Cap("database", "query:SELECT"), new List<Claims.Capability>()));
    }

    [Fact]
    public void PatternPrecedence()
    {
        Assert.True(CapMatch.MatchPattern("database:*", "database:query").Matched);
        Assert.Equal(1, CapMatch.MatchPattern("database:*", "database:query").Score);
        Assert.False(CapMatch.MatchPattern("database:*", "https:query").Matched);

        Assert.Equal(6, CapMatch.MatchPattern("a:b/c", "a:b/c").Score);
        Assert.Equal(5, CapMatch.MatchPattern("a:*/who", "a:b/who").Score);
        Assert.Equal(4, CapMatch.MatchPattern("a:b/**", "a:b/c/d/who").Score);
        Assert.Equal(5, CapMatch.MatchPattern("database:query:S*", "database:query:SELECT").Score);

        Assert.True(CapMatch.MatchPattern("a:S*e", "a:Some").Matched);
        Assert.True(CapMatch.MatchPattern("a:*:c", "a:b:c").Matched);
        Assert.False(CapMatch.MatchPattern("http:{GET,POST}:*", "http:GET:/v1/users").Matched);

        Assert.True(CapMatch.MatchPattern("a:**", "a:x:y").Matched);
        Assert.True(CapMatch.MatchPattern("a:**", "a:x/y:z").Matched);
        Assert.True(CapMatch.MatchPattern("a:**", "a:b").Matched);
        Assert.Equal(4, CapMatch.MatchPattern("a:**", "a:x/y:z").Score);

        Assert.True(CapMatch.MatchPattern("http:{GET,POST}:*", "http:GET:id").Matched);
        Assert.Equal(5, CapMatch.MatchPattern("http:{GET,POST}:*", "http:GET:id").Score);
        Assert.True(CapMatch.MatchPattern("http:[A-Z]*:*", "http:GET:id").Matched);
        Assert.Equal(5, CapMatch.MatchPattern("http:[A-Z]*:*", "http:GET:id").Score);

        Assert.True(CapMatch.MatchPattern("http:{GET,POST}", "http:GET").Matched);
        Assert.Equal(3, CapMatch.MatchPattern("http:{GET,POST}", "http:GET").Score);

        Assert.False(CapMatch.MatchPattern("a:**", "a").Matched);
    }

    [Fact]
    public void ParamsWithinBounds()
    {
        JsonNode grant = JwtJson.Parse("{\"max_rows\":1000,\"readonly\":true,\"tables\":[\"users\"],\"limit\":10.5}");
        Assert.True(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"max_rows\":500}")));
        Assert.False(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"max_rows\":2000}")));
        Assert.False(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"readonly\":false}")));
        Assert.True(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"tables\":[\"users\"]}")));
        Assert.False(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"tables\":[\"admins\"]}")));
        Assert.True(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"limit\":10.0}")));
        Assert.False(CapMatch.ParamsWithinGrant(grant, JwtJson.Parse("{\"limit\":11}")));
        Assert.True(CapMatch.ParamsWithinGrant(null, JwtJson.Parse("{\"max_rows\":999999}")));
    }
}
