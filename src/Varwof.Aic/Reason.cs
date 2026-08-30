using System;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Delegation authorization reason (audit/display only, not part of permission
/// decisions). Both fields are REQUIRED non-empty. DER:
/// SEQUENCE { UTF8String reasonCode, UTF8String description }.
/// </summary>
public sealed class Reason : IEquatable<Reason>
{
    public string ReasonCode { get; }
    public string Description { get; }

    public static readonly Reason Empty = new("", "");

    public Reason(string reasonCode, string description)
    {
        ReasonCode = reasonCode ?? throw new ArgumentNullException(nameof(reasonCode));
        Description = description ?? throw new ArgumentNullException(nameof(description));
    }

    public bool IsEmpty => ReasonCode.Length == 0 && Description.Length == 0;

    public byte[] Encode() => Der.DerEncode(Der.DerSequence(Der.Utf8(ReasonCode), Der.Utf8(Description)));

    public static Reason Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count != 2)
        {
            throw new AicException("Reason: expected 2 elements, got " + seq.Count);
        }
        return new Reason(Der.StringValue(seq[0]), Der.StringValue(seq[1]));
    }

    public bool Equals(Reason? other)
        => other is not null && ReasonCode == other.ReasonCode && Description == other.Description;

    public override bool Equals(object? obj) => Equals(obj as Reason);

    public override int GetHashCode() => HashCode.Combine(ReasonCode, Description);

    public override string ToString() => ReasonCode + ": " + Description;
}