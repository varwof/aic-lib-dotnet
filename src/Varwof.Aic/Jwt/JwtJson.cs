using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// JSON utilities for the JWT package. Mirrors Go types/aicjwt/jsonutil.go and
/// the semantic comparisons in claims.go. System.Text.Json backed.
/// </summary>
public static class JwtJson
{
    /// <summary>
    /// Shared wire options: snake_case member names, nulls omitted (Go
    /// omitempty), audience converter installed.
    /// </summary>
    public static readonly JsonSerializerOptions WireOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Converters = { new AudienceConverter() }
    };

    public static bool HasDuplicateKeys(byte[] raw)
    {
        if (raw is null || raw.Length == 0)
        {
            return false;
        }
        try
        {
            using JsonDocument doc = JsonDocument.Parse(raw, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            return WalkDuplicates(doc.RootElement);
        }
        catch
        {
            return false;
        }
    }

    private static bool WalkDuplicates(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>();
            foreach (JsonProperty prop in el.EnumerateObject())
            {
                if (!seen.Add(prop.Name))
                {
                    return true;
                }
            }
            foreach (JsonProperty prop in el.EnumerateObject())
            {
                if (WalkDuplicates(prop.Value))
                {
                    return true;
                }
            }
        }
        else if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement child in el.EnumerateArray())
            {
                if (WalkDuplicates(child))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static JsonNode Parse(byte[] raw)
    {
        try
        {
            return JsonNode.Parse(raw) ?? throw new JsonException("null root");
        }
        catch (Exception ex)
        {
            throw new AicException("json: invalid JSON: " + ex.Message);
        }
    }

    public static JsonNode Parse(string raw)
    {
        try
        {
            return JsonNode.Parse(raw) ?? throw new JsonException("null root");
        }
        catch (Exception ex)
        {
            throw new AicException("json: invalid JSON: " + ex.Message);
        }
    }

    public static JsonNode ToNode(object value)
    {
        try
        {
            return JsonSerializer.SerializeToNode(value, WireOptions)!;
        }
        catch (Exception ex)
        {
            throw new AicException("json: cannot convert to node: " + ex.Message);
        }
    }

    /// <summary>Compact serialized byte length of a JSON subtree (0 when absent).</summary>
    public static int CompactLength(JsonNode? node)
    {
        if (node is null)
        {
            return 0;
        }
        try
        {
            return Encoding.UTF8.GetByteCount(node.ToJsonString());
        }
        catch (Exception ex)
        {
            throw new AicException("json: cannot serialize: " + ex.Message);
        }
    }

    /// <summary>Semantic JSON equality (member order and whitespace ignored).</summary>
    public static bool JsonEqual(object? a, object? b)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }
        if (a is null || b is null)
        {
            return false;
        }
        if (a is JsonNode na && b is JsonNode nb)
        {
            return JsonNode.DeepEquals(na, nb);
        }
        try
        {
            JsonNode an = JsonSerializer.SerializeToNode(a, WireOptions)!;
            JsonNode bn = JsonSerializer.SerializeToNode(b, WireOptions)!;
            return JsonNode.DeepEquals(an, bn);
        }
        catch
        {
            return a.Equals(b);
        }
    }

    /// <summary>
    /// Numeric-bounded delegate for ParamsWithinGrant: agent values must stay
    /// within grant values (agent &lt;= grant for numbers), non-numeric values
    /// must be equal, arrays must be subsets, objects recurse.
    /// </summary>
    public static bool ParamsWithin(JsonNode? grant, JsonNode? agent)
    {
        if (grant is null || grant.GetValueKind() == JsonValueKind.Null)
        {
            return true;
        }
        return ParamsWithinStrict(grant, agent!);
    }

    private static bool ParamsWithinStrict(JsonNode grant, JsonNode agent)
    {
        if (grant is JsonObject go)
        {
            if (agent is not JsonObject ao)
            {
                return false;
            }
            foreach (var kv in ao)
            {
                if (!go.TryGetPropertyValue(kv.Key, out JsonNode? grantValue) || grantValue is null || grantValue.GetValueKind() == JsonValueKind.Null)
                {
                    return false;
                }
                if (!ParamsWithinStrict(grantValue, kv.Value!))
                {
                    return false;
                }
            }
            return true;
        }
        if (grant.GetValueKind() == JsonValueKind.Number)
        {
            if (agent.GetValueKind() != JsonValueKind.Number)
            {
                return false;
            }
            return NumLte(agent, grant);
        }
        if (grant.GetValueKind() == JsonValueKind.String)
        {
            return agent.GetValueKind() == JsonValueKind.String && agent.GetValue<string>()! == grant.GetValue<string>()!;
        }
        if (grant is JsonValue gv && (gv.GetValueKind() == JsonValueKind.True || gv.GetValueKind() == JsonValueKind.False))
        {
            return agent is JsonValue av && (av.GetValueKind() == JsonValueKind.True || av.GetValueKind() == JsonValueKind.False)
                && grant.GetValue<bool>()! == agent.GetValue<bool>()!;
        }
        if (grant is JsonArray ga)
        {
            if (agent is not JsonArray aa || aa is null || ga is null)
            {
                return false;
            }
            foreach (JsonNode? x in aa!)
            {
                bool found = false;
                foreach (JsonNode? y in ga!)
                {
                    if (JsonNode.DeepEquals(x, y))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }
        var grantJson = grant.ToJsonString();
        var agentJson = agent.ToJsonString();
        return grantJson == agentJson;
    }
    private static bool NumLte(JsonNode agent, JsonNode grant)
    {
        if (agent is JsonValue av && grant is JsonValue gv
            && av.TryGetValue<long>(out long al) && gv.TryGetValue<long>(out long gl))
        {
            return al <= gl;
        }
        double ad = ToDouble(agent);
        double gd = ToDouble(grant);
        return ad <= gd;
    }

    // Mirrors Go's json.Number.Float64() fallback (never throws, returns 0 on
    // non-numeric input), tolerating magnitudes beyond decimal's range.
    private static double ToDouble(JsonNode n)
    {
        if (n is JsonValue v && v.TryGetValue<double>(out double d))
        {
            return d;
        }
        return double.TryParse(n.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed) ? parsed : 0.0;
    }
}