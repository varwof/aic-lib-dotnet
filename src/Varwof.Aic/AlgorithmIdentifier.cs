using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// X.509-style AlgorithmIdentifier (SEQUENCE { OID [, params] }).
/// Used as the [0] EXPLICIT hashAlgo in PrincipalUid and as signatureAlgorithm
/// in DelegationAuthorization. Parameters holds the raw DER bytes of the
/// optional parameters element (or null when absent), matching Go's
/// asn1.RawValue handling.
/// </summary>
public sealed class AlgorithmIdentifier : IEquatable<AlgorithmIdentifier>
{
    public DerObjectIdentifier Oid { get; }
    public byte[]? Parameters { get; }

    public AlgorithmIdentifier(DerObjectIdentifier oid, byte[]? parameters)
    {
        Oid = oid ?? throw new ArgumentNullException(nameof(oid));
        Parameters = parameters is null ? null : (byte[])parameters.Clone();
    }

    public AlgorithmIdentifier(DerObjectIdentifier oid) : this(oid, null) { }

    public bool HasParameters() => Parameters is not null;

    public byte[] Encode()
    {
        Asn1Encodable[] elems = Parameters is null
            ? new Asn1Encodable[] { Oid }
            : new Asn1Encodable[] { Oid, FromParams(Parameters) };
        return Der.DerEncode(new DerSequence(elems));
    }

    private static Asn1Encodable FromParams(byte[] raw)
    {
        try
        {
            return Asn1Object.FromByteArray(raw);
        }
        catch (Exception ex)
        {
            throw new AicException("Invalid AlgorithmIdentifier parameters", ex);
        }
    }

    public static AlgorithmIdentifier Decode(Asn1Encodable e)
    {
        try
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(e);
            var oid = DerObjectIdentifier.GetInstance(seq[0]);
            byte[]? parameters = null;
            if (seq.Count > 1)
            {
                parameters = seq[1].ToAsn1Object().GetDerEncoded();
            }
            return new AlgorithmIdentifier(oid, parameters);
        }
        catch (Exception ex)
        {
            throw new AicException("Bad AlgorithmIdentifier", ex);
        }
    }

    public static AlgorithmIdentifier Parse(byte[] derBytes)
    {
        try
        {
            return Decode(Der.FromBytes(derBytes));
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("Bad AlgorithmIdentifier DER", ex);
        }
    }

    public bool Equals(AlgorithmIdentifier? other) => other is not null
        && Oid.Equals(other.Oid)
        && (Parameters ?? Array.Empty<byte>()).SequenceEqual(other.Parameters ?? Array.Empty<byte>());

    public override bool Equals(object? obj) => Equals(obj as AlgorithmIdentifier);

    public override int GetHashCode()
    {
        int h = Oid.GetHashCode();
        h = h * 31 + (Parameters is null ? 0 : Parameters.Length);
        return h;
    }

    public override string ToString() => Parameters is null ? Oid.Id : Oid.Id + " (params)";
}