using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Future delegation-depth control extension (OID .1.1.4, draft §3.7).
/// SEQUENCE { INTEGER chainDepth, INTEGER maxDepth }. Currently an advisory
/// structure; enforcement is a future feature in both the Go and the mobility
/// SDKs.
/// </summary>
public sealed class DelegationDepthControl : IEquatable<DelegationDepthControl>
{
    public int ChainDepth { get; }
    public int MaxDepth { get; }

    public DelegationDepthControl(int chainDepth, int maxDepth)
    {
        ChainDepth = chainDepth;
        MaxDepth = maxDepth;
    }

    public byte[] Encode() => Der.DerEncode(Der.DerSequence(Der.Integer(ChainDepth), Der.Integer(MaxDepth)));

    public static DelegationDepthControl Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count != 2)
        {
            throw new AicException("DelegationDepthControl: expected 2 elements, got " + seq.Count);
        }
        return new DelegationDepthControl(Der.IntValue(seq[0]), Der.IntValue(seq[1]));
    }

    public static DelegationDepthControl Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

    public bool Equals(DelegationDepthControl? other) => other is not null && ChainDepth == other.ChainDepth && MaxDepth == other.MaxDepth;
    public override bool Equals(object? obj) => Equals(obj as DelegationDepthControl);
    public override int GetHashCode() => System.HashCode.Combine(ChainDepth, MaxDepth);
}