using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// The AIC X.509v3 extension value (draft §5.1 / Go types.AIC).
/// DER:
/// SEQUENCE {
///   INTEGER version                     (DEFAULT 1)
///   UTF8String agentId
///   PrincipalUid principalUid
///   SEQUENCE OF Capability capabilities
///   INTEGER delegationMode              (DEFAULT 0)
///   [0] EXPLICIT SEQUENCE OF Capability authorizationConstraints OPTIONAL
///   DelegationAuthorization delegationAuthorization OPTIONAL   (required by spec)
///   [1] EXPLICIT SEQUENCE OF ExtField extensions OPTIONAL
/// }
/// </summary>
public sealed class Aic : IEquatable<Aic>
{
    public int Version { get; }
    public string AgentId { get; }
    public PrincipalUid PrincipalUid { get; }
    public IReadOnlyList<Capability> Capabilities { get; }
    public DelegationMode DelegationMode { get; }
    public IReadOnlyList<Capability> AuthorizationConstraints { get; }
    public DelegationAuthorization? DelegationAuthorization { get; }
    public IReadOnlyList<ExtField> Extensions { get; }

    public Aic(
        int version,
        string agentId,
        PrincipalUid principalUid,
        IReadOnlyList<Capability>? capabilities,
        DelegationMode delegationMode,
        IReadOnlyList<Capability>? authorizationConstraints,
        DelegationAuthorization? delegationAuthorization,
        IReadOnlyList<ExtField>? extensions)
    {
        Version = version;
        AgentId = agentId ?? throw new ArgumentNullException(nameof(agentId));
        PrincipalUid = principalUid ?? throw new ArgumentNullException(nameof(principalUid));
        Capabilities = capabilities ?? (IReadOnlyList<Capability>)Array.Empty<Capability>();
        DelegationMode = delegationMode;
        AuthorizationConstraints = authorizationConstraints ?? (IReadOnlyList<Capability>)Array.Empty<Capability>();
        DelegationAuthorization = delegationAuthorization;
        Extensions = extensions ?? (IReadOnlyList<ExtField>)Array.Empty<ExtField>();
    }

    public static AicBuilder Builder() => new();

    /// <summary>Copy with a (new) DelegationAuthorization attached.</summary>
    public Aic WithDelegationAuthorization(DelegationAuthorization da) => new(
        Version, AgentId, PrincipalUid, Capabilities, DelegationMode, AuthorizationConstraints, da, Extensions);

    /// <summary>Communication-form principal string {realm}:{identifier}:{fp}.</summary>
    public string Principal() => PrincipalUid.DisplayString();

    /// <summary>True when the agent carries at least one capability with the given scheme.</summary>
    public bool HasProtocol(string schemeId)
        => Capabilities.Any(c => c.SchemeId == schemeId);

    /// <summary>True when any capability full ID matches "required" (glob).</summary>
    public bool CheckPermission(string required)
        => Capabilities.Any(c => CapabilityMatcher.MatchCapability(c.FullId(), required));

    /// <summary>Full IDs of capabilities that match any granted pattern.</summary>
    public IReadOnlyList<string> IntersectPermissions(PrincipalAuthorization? pa)
        => pa is null ? Array.Empty<string>() : IntersectPermissions(pa.GrantIds());

    public IReadOnlyList<string> IntersectPermissions(IReadOnlyList<string> grantPatterns)
    {
        if (Capabilities.Count == 0 || grantPatterns.Count == 0)
        {
            return Array.Empty<string>();
        }
        var seen = new HashSet<string>();
        var result = new List<string>();
        foreach (Capability c in Capabilities)
        {
            string full = c.FullId();
            if (!seen.Add(full))
            {
                continue;
            }
            foreach (string p in grantPatterns)
            {
                if (CapabilityMatcher.MatchCapability(full, p))
                {
                    result.Add(full);
                    break;
                }
            }
        }
        return result;
    }

    public IReadOnlyList<string> IntersectPermissionsStringAny(string commaOrSpaceDelimited)
    {
        if (string.IsNullOrEmpty(commaOrSpaceDelimited))
        {
            return Array.Empty<string>();
        }
        var perms = new List<string>();
        foreach (string tok in commaOrSpaceDelimited.Split(new[] { ',', ' ' }))
        {
            if (!string.IsNullOrEmpty(tok))
            {
                perms.Add(tok);
            }
        }
        return perms.Count == 0 ? Array.Empty<string>() : IntersectPermissions(perms);
    }

    public byte[] Encode()
    {
        var elems = new List<Asn1Encodable>
        {
            Der.Integer(Version),
            Der.Utf8(AgentId),
            Asn1Object.FromByteArray(PrincipalUid.Encode()),
            EncodeCapabilities(Capabilities),
            Der.Integer((int)DelegationMode)
        };
        if (AuthorizationConstraints.Count > 0)
        {
            elems.Add(Der.Explicit(0, EncodeCapabilities(AuthorizationConstraints)));
        }
        if (DelegationAuthorization is not null && DelegationAuthorization.IsPresent())
        {
            elems.Add(Asn1Object.FromByteArray(DelegationAuthorization.Encode()));
        }
        if (Extensions.Count > 0)
        {
            elems.Add(Der.Explicit(1, EncodeExtensions(Extensions)));
        }
        return Der.DerEncode(Der.DerSequence(elems.ToArray()));
    }

    private static Asn1Object EncodeCapabilities(IReadOnlyList<Capability> caps)
    {
        var arr = new Asn1Encodable[caps.Count];
        for (int i = 0; i < caps.Count; i++)
        {
            arr[i] = Asn1Object.FromByteArray(caps[i].Encode());
        }
        return new DerSequence(arr).ToAsn1Object();
    }

    private static Asn1Object EncodeExtensions(IReadOnlyList<ExtField> exts)
    {
        var arr = new Asn1Encodable[exts.Count];
        for (int i = 0; i < exts.Count; i++)
        {
            arr[i] = Asn1Object.FromByteArray(exts[i].Encode());
        }
        return new DerSequence(arr).ToAsn1Object();
    }

    public static Aic Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count < 5)
        {
            throw new AicException("Aic: expected at least 5 elements, got " + seq.Count);
        }
        int version = Der.IntValue(seq[0]);
        string agentId = Der.StringValue(seq[1]);
        PrincipalUid uid = PrincipalUid.Decode(seq[2]);
        List<Capability> caps = DecodeCapabilities(seq[3]);
        var constraints = new List<Capability>();
        DelegationAuthorization? da = null;
        var exts = new List<ExtField>();
        DelegationMode? mode = null;
        for (int ix = 4; ix < seq.Count; ix++)
        {
            Asn1Encodable elem = seq[ix];
            Asn1Object? inner = Der.OptionalTagContent(elem, 0);
            if (inner is not null)
            {
                constraints = DecodeCapabilities(inner);
                continue;
            }
            inner = Der.OptionalTagContent(elem, 1);
            if (inner is not null)
            {
                exts = DecodeExtensions(inner);
                continue;
            }
            if (elem.ToAsn1Object() is DerInteger)
            {
                mode = DelegationModes.FromValue(Der.IntValue(elem));
                continue;
            }
            if (elem.ToAsn1Object() is Asn1Sequence)
            {
                da = DelegationAuthorization.Decode(elem);
                continue;
            }
            throw new AicException("Aic: unexpected element at index " + ix);
        }
        mode ??= DelegationMode.Authorized;
        return new Aic(version, agentId, uid, caps, mode.Value, constraints, da, exts);
    }

    public static Aic Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

    internal static List<Capability> DecodeCapabilities(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        var result = new List<Capability>(seq.Count);
        for (int i = 0; i < seq.Count; i++)
        {
            result.Add(Capability.Decode(seq[i]));
        }
        return result;
    }

    private static List<ExtField> DecodeExtensions(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        var result = new List<ExtField>(seq.Count);
        for (int i = 0; i < seq.Count; i++)
        {
            result.Add(ExtField.Decode(seq[i]));
        }
        return result;
    }

    public bool Equals(Aic? other) => other is not null
        && Version == other.Version
        && AgentId == other.AgentId
        && PrincipalUid.Equals(other.PrincipalUid)
        && Capabilities.SequenceEqual(other.Capabilities)
        && DelegationMode == other.DelegationMode
        && AuthorizationConstraints.SequenceEqual(other.AuthorizationConstraints)
        && Equals(DelegationAuthorization, other.DelegationAuthorization)
        && Extensions.SequenceEqual(other.Extensions);

    public override bool Equals(object? obj) => Equals(obj as Aic);

    public override int GetHashCode() => HashCode.Combine(Version, AgentId, PrincipalUid);
}

/// <summary>Fluent builder; da and constraints/actions can be added after construction.</summary>
public sealed class AicBuilder
{
    private int _version = 1;
    private string _agentId = "";
    private PrincipalUid? _principalUid;
    private readonly List<Capability> _capabilities = new();
    private DelegationMode _delegationMode = DelegationMode.Authorized;
    private readonly List<Capability> _authorizationConstraints = new();
    private DelegationAuthorization? _delegationAuthorization;
    private readonly List<ExtField> _extensions = new();

    public AicBuilder Version(int v) { _version = v; return this; }
    public AicBuilder AgentId(string id) { _agentId = id; return this; }
    public AicBuilder PrincipalUid(PrincipalUid uid) { _principalUid = uid; return this; }
    public AicBuilder Capability(Capability c) { _capabilities.Add(c); return this; }
    public AicBuilder Capabilities(IEnumerable<Capability> caps) { _capabilities.AddRange(caps); return this; }
    public AicBuilder SetDelegationMode(DelegationMode mode) { _delegationMode = mode; return this; }
    public AicBuilder Constraint(Capability c) { _authorizationConstraints.Add(c); return this; }
    public AicBuilder DelegationAuthorization(DelegationAuthorization da) { _delegationAuthorization = da; return this; }

    public IReadOnlyList<Capability> CapabilitiesView => _capabilities;
    public IReadOnlyList<Capability> ConstraintsView => _authorizationConstraints;
    public IReadOnlyList<ExtField> ExtensionsView => _extensions;

    public Aic Build()
    {
        if (_principalUid is null)
        {
            throw new AicException("Aic: principalUid is required");
        }
        return new Aic(_version, _agentId, _principalUid, _capabilities, _delegationMode,
            _authorizationConstraints, _delegationAuthorization, _extensions);
    }
}