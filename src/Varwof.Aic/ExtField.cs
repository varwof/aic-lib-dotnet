using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// A single extension slot inside AIC.extensions.
/// DER: SEQUENCE { OID extnId, BOOLEAN critical (default FALSE),
///       OCTET STRING extnValue }. Like the Go reference (no omitempty on the
/// BOOLEAN), critical is always emitted.
/// </summary>
public sealed class ExtField : IEquatable<ExtField>
{
    public DerObjectIdentifier ExtnId { get; }
    public bool Critical { get; }
    public byte[] ExtnValue { get; }

    public ExtField(DerObjectIdentifier extnId, bool critical, byte[] extnValue)
    {
        ExtnId = extnId ?? throw new ArgumentNullException(nameof(extnId));
        Critical = critical;
        ExtnValue = (byte[])(extnValue ?? throw new ArgumentNullException(nameof(extnValue))).Clone();
    }

    public byte[] Encode() => Der.DerEncode(Der.DerSequence(
        ExtnId,
        DerBoolean.GetInstance(Critical),
        new DerOctetString(ExtnValue)));

    public static ExtField Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count != 3)
        {
            throw new AicException("ExtField: expected 3 elements, got " + seq.Count);
        }
        var id = DerObjectIdentifier.GetInstance(seq[0]);
        bool crit = DerBoolean.GetInstance(seq[1]).IsTrue;
        byte[] value = Der.OctetValue(seq[2]);
        return new ExtField(id, crit, value);
    }

    public bool Equals(ExtField? other) => other is not null
        && Critical == other.Critical
        && ExtnId.Equals(other.ExtnId)
        && ExtnValue.SequenceEqual(other.ExtnValue);

    public override bool Equals(object? obj) => Equals(obj as ExtField);

    public override int GetHashCode()
    {
        int h = ExtnId.GetHashCode();
        h = h * 31 + (Critical ? 1 : 0);
        h = h * 31 + ExtnValue.Length;
        return h;
    }
}