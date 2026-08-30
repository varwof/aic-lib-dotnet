using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Varwof.Aic;

/// <summary>
/// Thin JSON helpers shared by the core and JWT packages (System.Text.Json
/// backed).
/// </summary>
public static class JsonUtil
{
    public static bool IsValidJson(byte[] raw)
    {
        if (raw is null || raw.Length == 0)
        {
            return false;
        }
        try
        {
            _ = JsonNode.Parse(raw);
            return true;
        }
        catch
        {
            return false;
        }
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

    /// <summary>
    /// True when the JSON document contains a duplicated member name at any
    /// nesting level (RFC 8725 §3.2; the Go validator rejects such tokens).
    /// </summary>
    public static bool HasDuplicateMemberNames(JsonNode? node)
    {
        if (node is null)
        {
            return false;
        }
        return WalkDuplicates(node);
    }

    private static bool WalkDuplicates(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            var seen = new HashSet<string>();
            foreach (var kv in obj)
            {
                if (!seen.Add(kv.Key))
                {
                    return true;
                }
            }
            foreach (var child in obj)
            {
                if (child.Value is not null && WalkDuplicates(child.Value))
                {
                    return true;
                }
            }
        }
        else if (node is JsonArray arr)
        {
            foreach (JsonNode? child in arr)
            {
                if (child is not null && WalkDuplicates(child))
                {
                    return true;
                }
            }
        }
        return false;
    }
}