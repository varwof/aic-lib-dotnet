using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Agent SPKI key binding (DA version 2). DER:
/// SEQUENCE { OCTET STRING keyHash, [0] EXPLICIT AlgorithmIdentifier hashAlgo OPTIONAL }.
/// </summary>
public sealed class AgentKeyBinding : IEquatable<AgentKeyBinding>
{
    public byte[] KeyHash { get; }
    public AlgorithmIdentifier? HashAlgo { get; }

    public AgentKeyBinding(byte[] keyHash, AlgorithmIdentifier? hashAlgo)
    {
        KeyHash = (byte[])(keyHash ?? throw new ArgumentNullException(nameof(keyHash))).Clone();
        HashAlgo = hashAlgo;
    }

    /// <summary>Effective hash algorithm OID (absent defaults to SHA-256).</summary>
    public DerObjectIdentifier HashAlgoOid()
        => HashAlgo?.Oid is null ? Oids.Sha256 : HashAlgo.Oid;

    public bool IsZero() => KeyHash.Length == 0;

    public byte[] Encode()
    {
        var elems = new System.Collections.Generic.List<Asn1Encodable>
        {
            new DerOctetString(KeyHash)
        };
        if (HashAlgo is not null)
        {
            elems.Add(Der.Explicit(0, Asn1Object.FromByteArray(HashAlgo.Encode())));
        }
        return Der.DerEncode(Der.DerSequence(elems.ToArray()));
    }

    public static AgentKeyBinding Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count < 1 || seq.Count > 2)
        {
            throw new AicException("AgentKeyBinding: expected 1-2 elements, got " + seq.Count);
        }
        byte[] keyHash = Der.OctetValue(seq[0]);
        AlgorithmIdentifier? hashAlgo = null;
        if (seq.Count == 2)
        {
            Asn1Object? inner = Der.OptionalTagContent(seq[1], 0);
            if (inner is null)
            {
                throw new AicException("AgentKeyBinding: second element must be [0] EXPLICIT AlgorithmIdentifier");
            }
            hashAlgo = AlgorithmIdentifier.Decode(inner);
        }
        return new AgentKeyBinding(keyHash, hashAlgo);
    }

    public bool Equals(AgentKeyBinding? other) => other is not null
        && KeyHash.SequenceEqual(other.KeyHash)
        && Equals(HashAlgo, other.HashAlgo);

    public override bool Equals(object? obj) => Equals(obj as AgentKeyBinding);

    public override int GetHashCode()
    {
        int h = HashCode.Combine(KeyHash.Length);
        if (HashAlgo is not null)
        {
            h = h * 31 + HashAlgo.GetHashCode();
        }
        return h;
    }
}
