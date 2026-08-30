using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// PrincipalAuthorization principal grants (Go types.PrincipalAuthorization).
/// SEQUENCE {
///   INTEGER version (DEFAULT 1),
///   SEQUENCE OF Capability grants OPTIONAL,
///   [0] EXPLICIT SEQUENCE OF Capability authorizationConstraints OPTIONAL,
///   [1] EXPLICIT DelegationPolicy delegationPolicy OPTIONAL,
///   [2] EXPLICIT SEQUENCE OF ExtField extensions OPTIONAL
/// }
/// Go's delegationPolicy asn1:"optional,explicit,tag:1" has no omitempty, so a
/// zero-valued policy is still emitted when the field precedes extensions;
/// null here means the optional field is omitted.
/// </summary>
public sealed class PrincipalAuthorization : IEquatable<PrincipalAuthorization>
{
    public int Version { get; }
    public IReadOnlyList<Capability> Grants { get; }
    public IReadOnlyList<Capability> Capabilities => Grants;
    public IReadOnlyList<Capability> AuthorizationConstraints { get; }
    public DelegationPolicy? DelegationPolicy { get; }
    public DelegationPolicy? Policy => DelegationPolicy;
    public IReadOnlyList<ExtField> Extensions { get; }
    public byte[] PrincipalKeyHash { get; }
    public string PaId { get; }

    public PrincipalAuthorization(
        int version,
        IReadOnlyList<Capability>? grants,
        IReadOnlyList<Capability>? authorizationConstraints,
        DelegationPolicy? delegationPolicy,
        IReadOnlyList<ExtField>? extensions,
        byte[]? principalKeyHash = null,
        string? paId = null)
    {
        Version = version;
        Grants = grants ?? (IReadOnlyList<Capability>)Array.Empty<Capability>();
        AuthorizationConstraints = authorizationConstraints ?? (IReadOnlyList<Capability>)Array.Empty<Capability>();
        DelegationPolicy = delegationPolicy;
        Extensions = extensions ?? (IReadOnlyList<ExtField>)Array.Empty<ExtField>();
        PrincipalKeyHash = principalKeyHash ?? Array.Empty<byte>();
        PaId = paId ?? "";
    }

    public static PrincipalAuthorizationBuilder Builder() => new();

    public IReadOnlyList<string> GrantIds()
    {
        var ids = new List<string>(Grants.Count);
        foreach (Capability g in Grants)
        {
            ids.Add(g.FullId());
        }
        return ids;
    }

    public bool AllowsRepresentative() => DelegationPolicy is not null && DelegationPolicy.AllowsRepresentative();

    public byte[] Encode()
    {
        var elems = new List<Asn1Encodable> { Der.Integer(Version) };
        if (Grants.Count > 0)
        {
            elems.Add(EncodeCapabilities(Grants));
        }
        if (AuthorizationConstraints.Count > 0)
        {
            elems.Add(Der.Explicit(0, EncodeCapabilities(AuthorizationConstraints)));
        }
        if (DelegationPolicy is not null)
        {
            elems.Add(Der.Explicit(1, Asn1Object.FromByteArray(DelegationPolicy.Encode())));
        }
        if (Extensions.Count > 0)
        {
            elems.Add(Der.Explicit(2, EncodeExtensions(Extensions)));
        }
        return Der.DerEncode(Der.DerSequence(elems.ToArray()));
    }

    public static PrincipalAuthorization Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count < 1)
        {
            throw new AicException("PrincipalAuthorization: empty SEQUENCE");
        }
        int version = Der.IntValue(seq[0]);
        var grants = new List<Capability>();
        var constraints = new List<Capability>();
        DelegationPolicy? policy = null;
        var exts = new List<ExtField>();
        for (int ix = 1; ix < seq.Count; ix++)
        {
            Asn1Encodable elem = seq[ix];
            Asn1Object? inner;
            if ((inner = Der.OptionalTagContent(elem, 0)) is not null)
            {
                constraints = Aic.DecodeCapabilities(inner);
            }
            else if ((inner = Der.OptionalTagContent(elem, 1)) is not null)
            {
                policy = DelegationPolicy.Decode(inner);
            }
            else if ((inner = Der.OptionalTagContent(elem, 2)) is not null)
            {
                exts = DecodeExtensions(inner);
            }
            else
            {
                grants = Aic.DecodeCapabilities(elem);
            }
        }
        return new PrincipalAuthorization(version, grants, constraints, policy, exts);
    }

    public static PrincipalAuthorization Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

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

    private static List<ExtField> DecodeExtensions(Asn1Encodable inner)
    {
        Asn1Sequence s = Der.Seq(inner);
        var result = new List<ExtField>(s.Count);
        for (int i = 0; i < s.Count; i++)
        {
            result.Add(ExtField.Decode(s[i]));
        }
        return result;
    }

    public bool Equals(PrincipalAuthorization? other) => other is not null
        && Version == other.Version
        && Grants.SequenceEqual(other.Grants)
        && AuthorizationConstraints.SequenceEqual(other.AuthorizationConstraints)
        && Equals(DelegationPolicy, other.DelegationPolicy)
        && Extensions.SequenceEqual(other.Extensions);

    public override bool Equals(object? obj) => Equals(obj as PrincipalAuthorization);
    public override int GetHashCode() => HashCode.Combine(Version, Grants.Count, AuthorizationConstraints.Count);
}

/// <summary>Fluent builder.</summary>
public sealed class PrincipalAuthorizationBuilder
{
    private int _version = 1;
    private readonly List<Capability> _grants = new();
    private readonly List<Capability> _constraints = new();
    private DelegationPolicy? _policy;
    private readonly List<ExtField> _extensions = new();

    public PrincipalAuthorizationBuilder Version(int v) { _version = v; return this; }
    public PrincipalAuthorizationBuilder Grant(Capability c) { _grants.Add(c); return this; }
    public PrincipalAuthorizationBuilder Grants(IEnumerable<Capability> caps) { _grants.AddRange(caps); return this; }
    public PrincipalAuthorizationBuilder Constraint(Capability c) { _constraints.Add(c); return this; }
    public PrincipalAuthorizationBuilder Policy(DelegationPolicy p) { _policy = p; return this; }

    public IReadOnlyList<Capability> GrantsView => _grants;

    public PrincipalAuthorization Build() => new(_version, _grants, _constraints, _policy, _extensions);
}