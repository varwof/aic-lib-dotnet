using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Delegation policy inside PrincipalAuthorization (Go types.DelegationPolicy).
/// DER: SEQUENCE { INTEGER version (DEFAULT 1), INTEGER maxAgents (DEFAULT 1),
///       INTEGER allowedMode (DEFAULT 0), [0] EXPLICIT INTEGER maxSessionHours OPTIONAL }.
/// </summary>
public sealed class DelegationPolicy : IEquatable<DelegationPolicy>
{
    public int Version { get; }
    public int MaxAgents { get; }
    public int AllowedMode { get; }
    public int? MaxSessionHours { get; }
    public IReadOnlyList<PrincipalUid> Principals { get; } = Array.Empty<PrincipalUid>();

    public static readonly DelegationPolicy Default = new(1, 1, 0, null);

    public DelegationPolicy(int version, int maxAgents, int allowedMode, int? maxSessionHours)
    {
        Version = version;
        MaxAgents = maxAgents;
        AllowedMode = allowedMode;
        MaxSessionHours = maxSessionHours;
    }

    public bool AllowsRepresentative() => AllowedMode == 1;

    public byte[] Encode()
    {
        var elems = new List<Asn1Encodable>
        {
            Der.Integer(Version),
            Der.Integer(MaxAgents),
            Der.Integer(AllowedMode)
        };
        if (MaxSessionHours is not null)
        {
            elems.Add(Der.Explicit(0, Der.Integer(MaxSessionHours.Value)));
        }
        return Der.DerEncode(Der.DerSequence(elems.ToArray()));
    }

    public static DelegationPolicy Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count < 3 || seq.Count > 4)
        {
            throw new AicException("DelegationPolicy: expected 3-4 elements, got " + seq.Count);
        }
        int version = Der.IntValue(seq[0]);
        int maxAgents = Der.IntValue(seq[1]);
        int allowedMode = Der.IntValue(seq[2]);
        int? maxSessionHours = null;
        if (seq.Count == 4)
        {
            Asn1Object? inner = Der.OptionalTagContent(seq[3], 0);
            if (inner is null)
            {
                throw new AicException("DelegationPolicy: fourth element must be [0] EXPLICIT INTEGER");
            }
            maxSessionHours = Der.IntValue(inner);
        }
        return new DelegationPolicy(version, maxAgents, allowedMode, maxSessionHours);
    }

    public bool Equals(DelegationPolicy? other) => other is not null
        && Version == other.Version
        && MaxAgents == other.MaxAgents
        && AllowedMode == other.AllowedMode
        && MaxSessionHours == other.MaxSessionHours;

    public override bool Equals(object? obj) => Equals(obj as DelegationPolicy);
    public override int GetHashCode() => HashCode.Combine(Version, MaxAgents, AllowedMode, MaxSessionHours);
}