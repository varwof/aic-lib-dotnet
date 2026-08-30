using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// A protocolized capability container (draft §5.1 / Go types.Capability).
/// The full permission identifier is "schemeId:capabilityId" (FullId) and all
/// matching/authorization decisions MUST use it.
/// DER: SEQUENCE { UTF8String schemeId, UTF8String capabilityId,
///       [0] EXPLICIT OCTET STRING OPTIONAL }.
/// </summary>
public sealed class Capability : IEquatable<Capability>
{
    public string SchemeId { get; }
    public string CapabilityId { get; }
    public byte[]? Parameters { get; }

    public Capability(string schemeId, string capabilityId, byte[]? parameters)
    {
        SchemeId = schemeId ?? throw new ArgumentNullException(nameof(schemeId));
        CapabilityId = capabilityId ?? throw new ArgumentNullException(nameof(capabilityId));
        Parameters = parameters is null ? null : (byte[])parameters.Clone();
    }

    public Capability(string schemeId, string capabilityId) : this(schemeId, capabilityId, null) { }

    /// <summary>Full permission identifier "scheme:capabilityId".</summary>
    public string FullId()
    {
        if (string.IsNullOrEmpty(SchemeId))
        {
            return CapabilityId;
        }
        return SchemeId + ":" + CapabilityId;
    }

    public bool HasParameters() => Parameters is { Length: > 0 };

    public byte[] Encode()
    {
        Asn1Encodable[] elems = HasParameters()
            ? new Asn1Encodable[] { Der.Utf8(SchemeId), Der.Utf8(CapabilityId), Der.Explicit(0, new DerOctetString(Parameters!)) }
            : new Asn1Encodable[] { Der.Utf8(SchemeId), Der.Utf8(CapabilityId) };
        return Der.DerEncode(Der.DerSequence(elems));
    }

    public static Capability Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count < 2 || seq.Count > 3)
        {
            throw new AicException("Capability: expected 2-3 elements, got " + seq.Count);
        }
        string scheme = Der.StringValue(seq[0]);
        string id = Der.StringValue(seq[1]);
        byte[]? parameters = null;
        if (seq.Count == 3)
        {
            Asn1Object? inner = Der.OptionalTagContent(seq[2], 0);
            if (inner is null)
            {
                throw new AicException("Capability: third element must be [0] EXPLICIT OCTET STRING");
            }
            parameters = Der.OctetValue(inner);
        }
        return new Capability(scheme, id, parameters);
    }

    public static Capability Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

    public bool Equals(Capability? other) => other is not null
        && SchemeId == other.SchemeId
        && CapabilityId == other.CapabilityId
        && (Parameters ?? Array.Empty<byte>()).SequenceEqual(other.Parameters ?? Array.Empty<byte>());

    public override bool Equals(object? obj) => Equals(obj as Capability);

    public override int GetHashCode()
    {
        unchecked
        {
            int h = SchemeId.GetHashCode();
            h = h * 31 + CapabilityId.GetHashCode();
            if (Parameters is not null)
            {
                h = h * 31 + System.HashCode.Combine(Parameters.Length, Parameters[0]);
            }
            return h;
        }
    }

    public override string ToString() => FullId();
}