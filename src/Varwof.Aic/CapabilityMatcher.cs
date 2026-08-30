using System;
using System.Collections.Generic;

namespace Varwof.Aic;

/// <summary>
/// Capability ID matching (glob) and priority-based rule decisions.
/// Port of Go types/match_priority.go and the MatchCapability /
/// matchDoubleStar helpers in types/aic.go.
///
/// IDs and patterns are segmented on ':'. A segment may then also be globbed
/// on '/'; '*' matches any single segment (or within a segment any char run
/// not crossing '/'), '?' a single char and '**' matches one or more
/// cross-segment parts.
/// </summary>
public static class CapabilityMatcher
{
    /// <summary>
    /// Mirrors Go MatchCapability: exact, then "**"/"*", then path-style glob,
    /// then a single "**" split.
    /// </summary>
    public static bool MatchCapability(string? id, string? pattern)
    {
        if (id is null || pattern is null)
        {
            return false;
        }
        if (id == pattern)
        {
            return true;
        }
        if (pattern is "**" or "*")
        {
            return true;
        }
        if (GlobMatch(pattern, id, '/'))
        {
            return true;
        }
        if (pattern.Contains("**"))
        {
            return MatchDoubleStar(id, pattern);
        }
        return false;
    }

    /// <summary>
    /// Mirrors Go matchDoubleStar: splits on "**", trims the trailing/leading
    /// "/" around it, then validates the leftover segments are non-empty and
    /// not "..".
    /// </summary>
    internal static bool MatchDoubleStar(string id, string pattern)
    {
        string[] parts = pattern.Split(new[] { "**" }, StringSplitOptions.None);
        if (parts.Length != 2)
        {
            return false;
        }
        string prefix = StripTrailingSlash(parts[0]);
        string suffix = StripLeadingSlash(parts[1]);

        string remaining = id;
        if (prefix.Length > 0)
        {
            if (!remaining.StartsWith(prefix, StringComparison.Ordinal))
            {
                return false;
            }
            remaining = remaining.Substring(prefix.Length);
            remaining = StripLeadingSlash(remaining);
        }
        if (suffix.Length > 0)
        {
            if (!remaining.EndsWith(suffix, StringComparison.Ordinal))
            {
                return false;
            }
            remaining = remaining.Substring(0, remaining.Length - suffix.Length);
            remaining = StripTrailingSlash(remaining);
        }
        if (remaining.Length == 0)
        {
            return true;
        }
        foreach (string seg in remaining.Split('/'))
        {
            if (seg.Length == 0 || seg == "..")
            {
                return false;
            }
        }
        return true;
    }

    private static string StripLeadingSlash(string s)
    {
        int i = 0;
        while (i < s.Length && s[i] == '/')
        {
            i++;
        }
        return s.Substring(i);
    }

    private static string StripTrailingSlash(string s)
    {
        int i = s.Length;
        while (i > 0 && s[i - 1] == '/')
        {
            i--;
        }
        return s.Substring(0, i);
    }

    // ---- priority matcher (port of match_priority.go) ----

    public static int MatchCapabilityPriority(string? id, string? pattern)
    {
        if (id is null || pattern is null)
        {
            return MatchPriority.NoMatch;
        }
        if (id == pattern)
        {
            return MatchPriority.Exact;
        }
        if (pattern is "*" or "**" or "*:*")
        {
            return MatchPriority.Global;
        }
        string[] idSegs = SplitNonEmpty(id);
        string[] patSegs = SplitNonEmpty(pattern);
        if (idSegs.Length == 0 || patSegs.Length == 0)
        {
            return MatchPriority.NoMatch;
        }
        // scheme wildcard: first segment "*", remaining segments exact (no wildcard)
        if (patSegs.Length >= 2 && patSegs[0] == "*" && !SegmentsContainWildcard(patSegs, 1))
        {
            if (idSegs.Length == patSegs.Length && SegmentsEqual(idSegs, patSegs, 1))
            {
                return MatchPriority.Scheme;
            }
        }
        if (SegmentsContainDoubleStar(patSegs))
        {
            if (MatchDoubleStarSegments(idSegs, patSegs))
            {
                return MatchPriority.Multi;
            }
        }
        if (idSegs.Length == patSegs.Length && MatchSingleSegments(idSegs, patSegs))
        {
            return MatchPriority.Single;
        }
        return MatchPriority.NoMatch;
    }

    /// <summary>
    /// Decision over a rule set: the highest-priority matching rule wins; at
    /// equal priority deny overrides allow; no match yields Matched=false
    /// (caller applies default, typically deny).
    /// </summary>
    public static CapabilityRuleMatch MatchCapabilityRules(string id, IReadOnlyList<CapabilityRule> rules)
    {
        CapabilityRuleMatch best = CapabilityRuleMatch.NoMatch;
        foreach (CapabilityRule r in rules)
        {
            int p = MatchCapabilityPriority(id, r.Pattern);
            if (p > best.Priority)
            {
                best = new CapabilityRuleMatch(true, r.Deny, p, r.Pattern);
            }
            else if (p == best.Priority && p > 0 && r.Deny && !best.Deny)
            {
                best = new CapabilityRuleMatch(true, true, p, r.Pattern);
            }
        }
        return best;
    }

    private static bool SegmentsContainWildcard(string[] segs, int from)
    {
        for (int i = from; i < segs.Length; i++)
        {
            if (segs[i].Contains('*') || segs[i].Contains('?'))
            {
                return true;
            }
        }
        return false;
    }

    private static bool SegmentsContainDoubleStar(string[] segs)
    {
        foreach (string s in segs)
        {
            if (s == "**")
            {
                return true;
            }
        }
        return false;
    }

    private static bool SegmentsEqual(string[] a, string[] b, int from)
    {
        if (a.Length - from != b.Length - from)
        {
            return false;
        }
        for (int i = from; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Segment match: literal, "*" or intra-segment glob ("*"/"?").</summary>
    private static bool MatchSingleSegment(string idSeg, string patSeg)
    {
        if (patSeg == "*")
        {
            return true;
        }
        if (patSeg.Contains('*') || patSeg.Contains('?'))
        {
            return GlobMatch(patSeg, idSeg, '/');
        }
        return idSeg == patSeg;
    }

    private static bool MatchSingleSegments(string[] idSegs, string[] patSegs)
    {
        for (int i = 0; i < patSegs.Length; i++)
        {
            if (patSegs[i] == "**")
            {
                return false;
            }
            if (!MatchSingleSegment(idSegs[i], patSegs[i]))
            {
                return false;
            }
        }
        return true;
    }

    private static bool MatchDoubleStarSegments(string[] idSegs, string[] patSegs)
    {
        int first = -1;
        int last = -1;
        for (int i = 0; i < patSegs.Length; i++)
        {
            if (patSegs[i] == "**")
            {
                if (first == -1)
                {
                    first = i;
                }
                last = i;
            }
        }
        if (first == -1)
        {
            return false;
        }
        if (first > idSegs.Length)
        {
            return false;
        }
        for (int i = 0; i < first; i++)
        {
            if (!MatchSingleSegment(idSegs[i], patSegs[i]))
            {
                return false;
            }
        }
        int suffixLen = patSegs.Length - last - 1;
        if (first + suffixLen > idSegs.Length)
        {
            return false;
        }
        for (int i = 0; i < suffixLen; i++)
        {
            if (!MatchSingleSegment(idSegs[idSegs.Length - suffixLen + i], patSegs[last + 1 + i]))
            {
                return false;
            }
        }
        return true;
    }

    private static string[] SplitNonEmpty(string s)
    {
        string[] raw = s.Split(':');
        var outList = new List<string>(raw.Length);
        foreach (string r in raw)
        {
            if (r.Length > 0)
            {
                outList.Add(r);
            }
        }
        return outList.ToArray();
    }

    // ---- glob primitive (path/filepath.Match semantics, separator '/') ----

    /// <summary>
    /// Shell glob with "* ? [..]" support and separator-sensitivity, ported
    /// from Go's path.Match/filepath.Match (separator '/'). A malformed
    /// pattern (e.g. unterminated class) is a no-match.
    /// </summary>
    public static bool GlobMatch(string? pattern, string? name, char separator)
    {
        if (pattern is null || name is null)
        {
            return false;
        }
        return MatchPattern(pattern, name, separator);
    }

    private static bool MatchPattern(string pattern, string name, char separator)
    {
        if (!pattern.Contains('*') && !pattern.Contains('?') && !pattern.Contains('['))
        {
            return pattern == name;
        }
        ScanResult sr = ScanChunk(pattern, separator);
        while (true)
        {
            bool star = sr.Star;
            string chunk = sr.Chunk;
            string rest = sr.Rest;
            if (star && chunk.Length == 0)
            {
                // trailing '*' matches the rest of the name unless it contains a separator
                return !name.Contains(separator);
            }
            MatchResult t = MatchChunk(chunk, name, separator);
            if (star)
            {
                if (t.Ok)
                {
                    string name0 = name;
                    string remainder0 = t.Remainder;
                    if (MatchRest(rest, remainder0, separator))
                    {
                        return true;
                    }
                    for (int i = 0; i < name0.Length && name0[i] != separator; i++)
                    {
                        MatchResult t2 = MatchChunk(chunk, name0.Substring(i + 1), separator);
                        if (t2.Ok && MatchRest(rest, t2.Remainder, separator))
                        {
                            return true;
                        }
                    }
                    return false;
                }
                for (int i = 0; i < name.Length && name[i] != separator; i++)
                {
                    MatchResult t2 = MatchChunk(chunk, name.Substring(i + 1), separator);
                    if (t2.Ok && MatchRest(rest, t2.Remainder, separator))
                    {
                        return true;
                    }
                }
                return false;
            }
            if (!t.Ok)
            {
                return false;
            }
            name = t.Remainder;
            bool hasStar = rest.Contains('*') || rest.Contains('?') || rest.Contains('[');
            if (!hasStar)
            {
                return rest == name;
            }
            sr = ScanChunk(rest, separator);
        }
    }

    private static bool MatchRest(string rest, string name, char separator)
    {
        if (rest.Length == 0)
        {
            return name.Length == 0;
        }
        return MatchPattern(rest, name, separator);
    }

    private readonly record struct ScanResult(bool Star, string Chunk, string Rest);

    private readonly record struct MatchResult(bool Ok, string Remainder);

    /// <summary>Split the leading chunk from a pattern (Go path.scanChunk).</summary>
    private static ScanResult ScanChunk(string pattern, char separator)
    {
        bool star = false;
        if (pattern.Length > 0 && pattern[0] == '*')
        {
            star = true;
            pattern = pattern.Substring(1);
        }
        bool inrange = false;
        int i;
        for (i = 0; i < pattern.Length; i++)
        {
            char c = pattern[i];
            switch (c)
            {
                case '\\':
                    if (i + 1 < pattern.Length)
                    {
                        i++;
                    }
                    break;
                case '[':
                    inrange = true;
                    break;
                case ']':
                    inrange = false;
                    break;
                case '*':
                    if (!inrange)
                    {
                        return new ScanResult(star, pattern.Substring(0, i), pattern.Substring(i));
                    }
                    break;
            }
        }
        return new ScanResult(star, pattern, "");
    }

    /// <summary>Match a single chunk (no unescaped '*') against a name prefix (Go matchChunk).</summary>
    private static MatchResult MatchChunk(string chunk, string name, char separator)
    {
        int ci = 0;
        int ni = 0;
        while (ci < chunk.Length)
        {
            char pc = chunk[ci];
            if (pc == '?')
            {
                if (ni >= name.Length || name[ni] == separator)
                {
                    return new MatchResult(false, "");
                }
                ci++;
                ni++;
                continue;
            }
            if (pc == '[')
            {
                if (ni >= name.Length || name[ni] == separator)
                {
                    return new MatchResult(false, "");
                }
                int j = ci + 1;
                bool negate = false;
                if (j < chunk.Length && (chunk[j] == '^' || chunk[j] == '!'))
                {
                    negate = true;
                    j++;
                }
                int close = -1;
                for (int k = j; k < chunk.Length; k++)
                {
                    if (chunk[k] == ']')
                    {
                        close = k;
                        break;
                    }
                }
                if (close < 0)
                {
                    return new MatchResult(false, ""); // bad pattern
                }
                char nc = name[ni];
                bool matched = false;
                bool firstChar = true;
                for (int k = j; k < close; k++)
                {
                    char c = chunk[k];
                    if (c == '\\')
                    {
                        c = chunk[++k];
                    }
                    if (!firstChar && k + 1 < close && chunk[k] == '-' && chunk[k + 1] != ']')
                    {
                        char hi = chunk[++k];
                        if (nc >= c && nc <= hi)
                        {
                            matched = true;
                        }
                        firstChar = false;
                        continue;
                    }
                    firstChar = false;
                    if (nc == c)
                    {
                        matched = true;
                    }
                }
                if (matched == negate)
                {
                    return new MatchResult(false, "");
                }
                ci = close + 1;
                ni++;
                continue;
            }
            if (ni >= name.Length || name[ni] != pc)
            {
                return new MatchResult(false, "");
            }
            ci++;
            ni++;
        }
        return new MatchResult(true, name.Substring(ni));
    }
}