using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// Constraint evaluation for AIC-JWT (draft-wei-aic-jwt Section 7).
/// Mirrors Go types/aicjwt/constraints.go.
/// </summary>
public static class Constraints
{
    /// <summary>Deployment-side inputs for constraint evaluation and capability plugins.</summary>
    public sealed class RequestContext
    {
        public DateTime Now { get; set; }
        public IPAddress? SourceIp { get; set; }
        public int ConcurrentCount { get; set; }
    }

    /// <summary>Evaluates one constraint capability.</summary>
    public delegate void ConstraintEvaluator(Claims.Capability capability, RequestContext ctx);

    /// <summary>Built-in constraint types of draft Section 7.</summary>
    public static readonly Dictionary<string, ConstraintEvaluator> BuiltinConstraintIds = new()
    {
        ["allowed-cidr"] = EvalAllowedCidr,
        ["max-concurrent"] = EvalMaxConcurrent,
        ["time-window"] = EvalTimeWindow
    };

    public static void EvalAllowedCidr(Claims.Capability c, RequestContext ctx)
    {
        if (c.Params is null || c.Params is not JsonArray)
        {
            throw new AicException("allowed-cidr: params must be a JSON array of CIDR strings");
        }
        if (ctx.SourceIp is null)
        {
            throw new AicException("allowed-cidr: no source IP in request context");
        }
        foreach (JsonNode? n in (JsonArray)c.Params)
        {
            if (n is null || n.GetValueKind() != JsonValueKind.String)
            {
                throw new AicException("allowed-cidr: params must be a JSON array of CIDR strings");
            }
            string cidrText = n.GetValue<string>();
            try
            {
                if (Cidr.Parse(cidrText).Contains(ctx.SourceIp))
                {
                    return;
                }
            }
            catch (AicException)
            {
                throw new AicException("allowed-cidr: invalid CIDR \"" + cidrText + "\"");
            }
        }
        throw new AicException("allowed-cidr: source IP " + ctx.SourceIp + " not in allowed ranges");
    }

    public static void EvalMaxConcurrent(Claims.Capability c, RequestContext ctx)
    {
        if (c.Params is not JsonObject obj || obj["max"] is null || obj["max"]!.GetValueKind() != JsonValueKind.Number)
        {
            throw new AicException("max-concurrent: params must be {\"max\": N}");
        }
        int max = obj["max"]!.GetValue<int>();
        if (max < 1)
        {
            throw new AicException("max-concurrent: max must be >= 1");
        }
        if (ctx.ConcurrentCount >= max)
        {
            throw new AicException("max-concurrent: concurrent count " + ctx.ConcurrentCount
                + " exceeds max " + max);
        }
    }

    public static void EvalTimeWindow(Claims.Capability c, RequestContext ctx)
    {
        if (c.Params is not JsonObject obj
            || obj["start"] is null || obj["start"]!.GetValueKind() != JsonValueKind.String
            || obj["end"] is null || obj["end"]!.GetValueKind() != JsonValueKind.String)
        {
            throw new AicException("time-window: params must be {\"start\":...,\"end\":...}");
        }
        string startS = obj["start"]!.GetValue<string>();
        string endS = obj["end"]!.GetValue<string>();
        int start = ParseHm(startS);
        int end = ParseHm(endS);
        DateTime now = ctx.Now == default ? DateTime.UtcNow : ctx.Now.ToUniversalTime();
        int cur = now.Hour * 60 + now.Minute;
        if (start <= end)
        {
            if (cur < start || cur > end)
            {
                throw new AicException("time-window: now " + string.Format("{0:00}:{1:00}", now.Hour, now.Minute)
                    + " outside [" + startS + "," + endS + "]");
            }
        }
        else if (cur < start && cur > end)
        {
            throw new AicException("time-window: now " + string.Format("{0:00}:{1:00}", now.Hour, now.Minute)
                + " outside overnight window [" + startS + "," + endS + "]");
        }
    }

    private static int ParseHm(string s)
    {
        string[] parts = s.Split(':');
        if (parts.Length != 2)
        {
            throw new AicException("time-window: invalid HH:MM \"" + s + "\"");
        }
        if (!int.TryParse(parts[0], out int h) || !int.TryParse(parts[1], out int m)
            || h < 0 || h > 23 || m < 0 || m > 59)
        {
            throw new AicException("time-window: invalid HH:MM \"" + s + "\"");
        }
        return h * 60 + m;
    }

    /// <summary>Evaluates all constraints with AND semantics. Unknown constraint
    /// types are ignored with an audit note unless strict is true; schemes other
    /// than varwof/constraint-v1 are rejected.</summary>
    public static List<string> EvaluateConstraints(List<Claims.Capability>? cs, RequestContext? ctx, bool strict)
    {
        var notes = new List<string>();
        if (cs is null)
        {
            return notes;
        }
        ctx ??= new RequestContext();
        foreach (Claims.Capability c in cs)
        {
            if (c.Scheme != "varwof/constraint-v1")
            {
                throw new AicException("constraint scheme \"" + c.Scheme
                    + "\" not allowed (must be varwof/constraint-v1)");
            }
            if (!BuiltinConstraintIds.TryGetValue(c.Id ?? "", out ConstraintEvaluator? eval))
            {
                if (strict)
                {
                    throw new AicException("unknown constraint type \"" + c.Id + "\" (strict mode)");
                }
                notes.Add("audit: unknown constraint type \"" + c.Id + "\" ignored");
                continue;
            }
            eval(c, ctx);
        }
        return notes;
    }
}