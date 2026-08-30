using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Varwof.Aic.Jwt;

/// <summary>
/// JSON claim models for AIC-JWT tokens (draft-wei-aic-jwt Sections 4 and 5).
/// Mirrors Go types/aicjwt/claims.go. Wire format uses snake_case member
/// names; members that are null are omitted matching Go's omitempty.
/// </summary>
public static class Claims
{
    /// <summary>JOSE protected header shared by all AIC-JWT token types.</summary>
    public sealed class Header
    {
        public string? Alg { get; set; }
        public string? Typ { get; set; }
        public string? Kid { get; set; }
        public List<string>? Crit { get; set; }
        public KeyHash.Jwk? Jwk { get; set; }
    }

    /// <summary>Audience accepts a JSON string or an array of strings (RFC 9068).</summary>
    public sealed record Audience
    {
        public Audience()
        {
            Values = Array.Empty<string>();
        }

        public Audience(string single)
        {
            Values = new[] { single };
        }

        public Audience(IReadOnlyList<string> values)
        {
            Values = values ?? Array.Empty<string>();
        }

        public IReadOnlyList<string> Values { get; init; }

        public bool Contains(string v)
        {
            foreach (string x in Values)
            {
                if (x == v)
                {
                    return true;
                }
            }
            return false;
        }

        public int Size => Values.Count;

        public string Get(int i) => Values[i];

        public override string ToString() => "[" + string.Join(", ", Values) + "]";
    }

    /// <summary>RFC 7800 confirmation claim (jkt form).</summary>
    public sealed class Cnf
    {
        public string? Jkt { get; set; }
    }

    /// <summary>Token Status List entry reference.</summary>
    public sealed class StatusRef
    {
        public int Idx { get; set; }
        public string Uri { get; set; } = "";
    }

    /// <summary>Principal is the principalUid equivalent (draft Section 5.1.2).</summary>
    public sealed class Principal
    {
        public string? Realm { get; set; }
        public string? Id { get; set; }
        public string? KeyHash { get; set; }
        public string? HashAlg { get; set; }
    }

    /// <summary>Capability is the unified container (draft Section 6.1).</summary>
    public sealed class Capability
    {
        public string? Scheme { get; set; }
        public string? Id { get; set; }
        public JsonNode? Params { get; set; }
    }

    /// <summary>Extension mirrors the AIC extensions slot.</summary>
    public sealed class Extension
    {
        public bool Critical { get; set; }
        public JsonNode? Value { get; set; }
    }

    /// <summary>AIC claims (draft Section 5.1.2).</summary>
    public sealed class AicClaims
    {
        public int Ver { get; set; }
        public Principal? Principal { get; set; }
        public string? DelegationMode { get; set; }
        public List<Capability>? Capabilities { get; set; }
        public List<Capability>? Constraints { get; set; }
        public int? ChainDepth { get; set; }
        public int? MaxDepth { get; set; }
        public Dictionary<string, Extension>? Extensions { get; set; }
    }

    /// <summary>Outer AIC-JWT payload (draft Section 5.1).</summary>
    public sealed class OuterClaims
    {
        public string? Iss { get; set; }
        public string? Sub { get; set; }
        public Audience? Aud { get; set; }
        public long Iat { get; set; }
        public long Exp { get; set; }
        public long? Nbf { get; set; }
        public string? Jti { get; set; }
        public Cnf? Cnf { get; set; }
        public string? Scope { get; set; }
        public string? ClientId { get; set; }
        public StatusRef? Status { get; set; }
        public AicClaims? Aic { get; set; }
        public string? Da { get; set; }
        public JsonNode? AuthorizationDetails { get; set; }
    }

    /// <summary>Delegation reason (draft Section 5.2).</summary>
    public sealed class Reason
    {
        public string? Code { get; set; }
        public string? Desc { get; set; }
    }

    /// <summary>Inner DA JWT payload, the JSON equivalent of DelegationAuthTbs.</summary>
    public sealed class DaClaims
    {
        public int Ver { get; set; }
        public string? AgentId { get; set; }
        public Principal? Principal { get; set; }
        public Reason? Reason { get; set; }
        public List<Capability>? Capabilities { get; set; }
        public string? DelegationMode { get; set; }
        public List<Capability>? Constraints { get; set; }
        public int RequestedLifetime { get; set; }
        public long Ts { get; set; }
        public string? Nonce { get; set; }
    }

    /// <summary>JSON equivalent of the ASN.1 DelegationPolicy (draft Section 5.3).</summary>
    public sealed class DelegationPolicy
    {
        public int MaxAgents { get; set; }
        public string? AllowedMode { get; set; }
        public int? MaxSessionHours { get; set; }
    }

    /// <summary>PA JWT payload (draft Section 5.3).</summary>
    public sealed class PaClaims
    {
        public int Ver { get; set; }
        public Principal? Principal { get; set; }
        public List<Capability>? Grants { get; set; }
        public List<Capability>? Constraints { get; set; }
        public DelegationPolicy? DelegationPolicy { get; set; }
        public Dictionary<string, Extension>? Extensions { get; set; }
    }
}

/// <summary>JsonConverter for Audience claims (string or array of strings).</summary>
public sealed class AudienceConverter : JsonConverter<Claims.Audience>
{
    public override Claims.Audience Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return new Claims.Audience(reader.GetString()!);
        }
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var list = new List<string>();
            reader.Read();
            while (reader.TokenType != JsonTokenType.EndArray)
            {
                if (reader.TokenType != JsonTokenType.String)
                {
                    throw new JsonException("aud array member is not a string");
                }
                list.Add(reader.GetString()!);
                reader.Read();
            }
            return new Claims.Audience(list);
        }
        throw new JsonException("aud must be a string or an array of strings");
    }

    public override void Write(Utf8JsonWriter writer, Claims.Audience value, JsonSerializerOptions options)
    {
        if (value.Values.Count == 1)
        {
            writer.WriteStringValue(value.Values[0]);
        }
        else
        {
            writer.WriteStartArray();
            foreach (string v in value.Values)
            {
                writer.WriteStringValue(v);
            }
            writer.WriteEndArray();
        }
    }
}