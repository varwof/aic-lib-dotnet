using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// Capability matching for AIC-JWT (draft-wei-aic-jwt Sections 6.2 and 6.3).
/// Mirrors Go types/aicjwt/capmatch.go: patterns split into tokens on ':' and
/// '/', '*' matches a single token, '**' crosses separators, and segments may
/// carry {a,b} alternation, [a-z] character classes and embedded '*'.
/// </summary>
public static class CapMatch
{
    public sealed record Match(bool Matched, int Score);

    public static string CapPattern(Claims.Capability c)
        => (c.Scheme ?? "") + ":" + (c.Id ?? "");

    /// <summary>
    /// Matches a target "scheme:id" string against a capability pattern and
    /// returns (matched, specificity). Precedence per 07-capability:
    /// exact(6) &gt; single-segment(5) &gt; multi-segment(4) &gt; alternation(3)
    /// &gt; char class(2) &gt; scheme-level(1).
    /// </summary>
    public static Match MatchPattern(string pattern, string target)
    {
        string[] ps = pattern.Split(':');
        string[] ts = target.Split(':');
        if (ps.Length == 2 && ps[1] == "*")
        {
            if (ts.Length >= 2 && ts[0] == ps[0])
            {
                return new Match(true, 1);
            }
            return new Match(false, 0);
        }
        if (!MatchTokens(Tokenize(ps), Tokenize(ts)))
        {
            return new Match(false, 0);
        }
        return new Match(true, PatternScore(ps));
    }

    /// <summary>
    /// Turns ":" and "/" separated segments into a flat token stream that keeps
    /// the separators, so '*' matches exactly one literal token and '**'
    /// matches across separators.
    /// </summary>
    internal static List<string> Tokenize(string[] segs)
    {
        var outList = new List<string>();
        for (int i = 0; i < segs.Length; i++)
        {
            if (i > 0)
            {
                outList.Add(":");
            }
            string s = segs[i];
            if (s is "*" or "**")
            {
                outList.Add(s);
                continue;
            }
            string[] parts = s.Split('/');
            for (int j = 0; j < parts.Length; j++)
            {
                if (j > 0)
                {
                    outList.Add("/");
                }
                outList.Add(parts[j]);
            }
        }
        return outList;
    }

    internal static bool MatchTokens(IReadOnlyList<string> p, IReadOnlyList<string> t)
    {
        if (p.Count == 0)
        {
            return t.Count == 0;
        }
        string head = p[0];
        if (head == "**")
        {
            if (t.Count == 0)
            {
                return false;
            }
            for (int i = 1; i <= t.Count; i++)
            {
                if (MatchTokens(Slice(p, 1, p.Count), Slice(t, i, t.Count)))
                {
                    return true;
                }
            }
            return false;
        }
        if (head == "*")
        {
            if (t.Count == 0 || t[0] is "/" or ":")
            {
                return false;
            }
            return MatchTokens(Slice(p, 1, p.Count), Slice(t, 1, t.Count));
        }
        if (t.Count == 0)
        {
            return false;
        }
        if (!MatchToken(head, t[0]))
        {
            return false;
        }
        return MatchTokens(Slice(p, 1, p.Count), Slice(t, 1, t.Count));
    }

    private static IReadOnlyList<string> Slice(IReadOnlyList<string> src, int from, int to)
    {
        var tmp = new List<string>(to - from);
        for (int i = from; i < to; i++)
        {
            tmp.Add(src[i]);
        }
        return tmp;
    }

    /// <summary>Matches a single token against a segment pattern that may carry
    /// '*', '{a,b}' alternation and [a-z] character classes.</summary>
    internal static bool MatchToken(string pattern, string target)
        => MatchTokenAt(pattern, 0, target, 0);

    private static bool MatchTokenAt(string p, int pi, string t, int ti)
    {
        while (true)
        {
            if (pi >= p.Length)
            {
                return ti >= t.Length;
            }
            char c = p[pi];
            if (c == '*')
            {
                for (int k = ti; k <= t.Length; k++)
                {
                    if (MatchTokenAt(p, pi + 1, t, k))
                    {
                        return true;
                    }
                }
                return false;
            }
            if (c == '{')
            {
                int end = p.IndexOf('}', pi + 1);
                if (end < 0)
                {
                    return false;
                }
                string[] alts = p.Substring(pi + 1, end - pi - 1).Split(',');
                foreach (string alt in alts)
                {
                    if (ti + alt.Length <= t.Length
                        && string.CompareOrdinal(t, ti, alt, 0, alt.Length) == 0
                        && MatchTokenAt(p, end + 1, t, ti + alt.Length))
                    {
                        return true;
                    }
                }
                return false;
            }
            if (c == '[')
            {
                int end = p.IndexOf(']', pi + 1);
                if (end < 0 || ti >= t.Length)
                {
                    return false;
                }
                if (!InCharClass(p.Substring(pi + 1, end - pi - 1), t[ti]))
                {
                    return false;
                }
                pi = end + 1;
                ti = ti + 1;
                continue;
            }
            if (ti >= t.Length || t[ti] != c)
            {
                return false;
            }
            pi = pi + 1;
            ti = ti + 1;
        }
    }

    private static bool InCharClass(string body, char ch)
    {
        for (int i = 0; i < body.Length; i++)
        {
            if (i + 2 < body.Length && body[i + 1] == '-')
            {
                if (body[i] <= ch && ch <= body[i + 2])
                {
                    return true;
                }
                i += 2;
                continue;
            }
            if (body[i] == ch)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Ranks a matched pattern's specificity (07-capability precedence).</summary>
    internal static int PatternScore(string[] ps)
    {
        if (ps.Length == 2 && ps[1] == "*")
        {
            return 1;
        }
        bool hasDouble = false, hasStar = false, hasAlt = false, hasClass = false;
        foreach (string s in ps)
        {
            if (s.Contains("**"))
            {
                hasDouble = true;
            }
            if (s.Contains('*'))
            {
                hasStar = true;
            }
            if (s.Contains('{'))
            {
                hasAlt = true;
            }
            if (s.Contains('['))
            {
                hasClass = true;
            }
        }
        if (hasDouble)
        {
            return 4;
        }
        if (hasStar)
        {
            return 5;
        }
        if (hasAlt)
        {
            return 3;
        }
        if (hasClass)
        {
            return 2;
        }
        return 6;
    }

    /// <summary>Evaluates a request capability against the allowed capabilities
    /// using the glob rules and precedence of draft Section 6.2. The highest-
    /// precedence matching rule decides; no match denies.</summary>
    public static bool MatchCapabilities(IReadOnlyList<Claims.Capability>? allowed, Claims.Capability req)
    {
        string target = CapPattern(req);
        int best = 0;
        if (allowed is null)
        {
            return false;
        }
        foreach (Claims.Capability c in allowed)
        {
            Match m = MatchPattern(CapPattern(c), target);
            if (m.Matched && m.Score > best)
            {
                best = m.Score;
            }
        }
        return best > 0;
    }

    /// <summary>Reports whether agent params stay within the grant's parameter
    /// bounds: agent numbers must be &lt;= grant numbers, other values equal,
    /// arrays subsets. Absent grants trivially bound.</summary>
    public static bool ParamsWithinGrant(JsonNode? grant, JsonNode? agent)
    {
        if (grant is null || grant.GetValueKind() == JsonValueKind.Null
            || agent is null || agent.GetValueKind() == JsonValueKind.Null)
        {
            return true;
        }
        return JwtJson.ParamsWithin(grant, agent);
    }

    /// <summary>Reports whether an agent capability is a capability-level and
    /// parameter-level subset of the principal grants (draft Section 8.2).</summary>
    public static bool CapabilitySubset(Claims.Capability agent, List<Claims.Capability>? grants)
    {
        string target = CapPattern(agent);
        int best = 0;
        if (grants is null)
        {
            return false;
        }
        foreach (Claims.Capability g in grants)
        {
            Match m = MatchPattern(CapPattern(g), target);
            if (!m.Matched || m.Score <= best)
            {
                continue;
            }
            if (!ParamsWithinGrant(g.Params, agent.Params))
            {
                continue;
            }
            best = m.Score;
        }
        return best > 0;
    }
}