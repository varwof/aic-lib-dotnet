using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Delegation authorization cryptographic evidence (draft §3 / Go
/// types.DelegationAuthorization).
/// Field order: reason, requestedLifetime, timestamp, nonce,
/// signatureAlgorithm, signatureValue.
/// DER: SEQUENCE { Reason, INTEGER requestedLifetime (DEFAULT 0),
///       GeneralizedTime timestamp, OCTET STRING nonce,
///       AlgorithmIdentifier signatureAlgorithm, OCTET STRING signatureValue }.
/// </summary>
public sealed class DelegationAuthorization : IEquatable<DelegationAuthorization>
{
    public Reason Reason { get; }
    public int RequestedLifetime { get; }
    public DateTime Timestamp { get; }
    public byte[]? Nonce { get; }
    public AlgorithmIdentifier SignatureAlgorithm { get; }
    public byte[]? SignatureValue { get; }

    public DelegationAuthorization(
        Reason reason,
        int requestedLifetime,
        DateTime timestamp,
        byte[]? nonce,
        AlgorithmIdentifier signatureAlgorithm,
        byte[]? signatureValue)
    {
        Reason = reason ?? throw new ArgumentNullException(nameof(reason));
        RequestedLifetime = requestedLifetime;
        Timestamp = timestamp;
        Nonce = nonce is null ? null : (byte[])nonce.Clone();
        SignatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
        SignatureValue = signatureValue is null ? null : (byte[])signatureValue.Clone();
    }

    /// <summary>Mirrors Go IsPresent().</summary>
    public bool IsPresent()
        => !string.IsNullOrEmpty(Reason.ReasonCode)
           || !string.IsNullOrEmpty(Reason.Description)
           || (SignatureValue is { Length: > 0 })
           || (Nonce is { Length: > 0 })
           || RequestedLifetime > 0;

    public byte[] Encode() => Der.DerEncode(Der.DerSequence(
        Asn1Object.FromByteArray(Reason.Encode()),
        Der.Integer(RequestedLifetime),
        Der.Generalized(Timestamp),
        new DerOctetString(Nonce ?? Array.Empty<byte>()),
        Asn1Object.FromByteArray(SignatureAlgorithm.Encode()),
        new DerOctetString(SignatureValue ?? Array.Empty<byte>())));

    public static DelegationAuthorization Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count != 6)
        {
            throw new AicException("DelegationAuthorization: expected 6 elements, got " + seq.Count);
        }
        Reason reason = Reason.Decode(seq[0]);
        int lifetime = Der.IntValue(seq[1]);
        DateTime ts = Der.ToInstant(Asn1GeneralizedTime.GetInstance(seq[2]));
        byte[] nonce = Der.OctetValue(seq[3]);
        AlgorithmIdentifier sigAlgo = AlgorithmIdentifier.Decode(seq[4]);
        byte[] sigValue = Der.OctetValue(seq[5]);
        return new DelegationAuthorization(reason, lifetime, ts, nonce, sigAlgo, sigValue);
    }

    public static DelegationAuthorization Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

    public bool Equals(DelegationAuthorization? other) => other is not null
        && RequestedLifetime == other.RequestedLifetime
        && Reason.Equals(other.Reason)
        && Timestamp == other.Timestamp
        && (Nonce ?? Array.Empty<byte>()).SequenceEqual(other.Nonce ?? Array.Empty<byte>())
        && SignatureAlgorithm.Equals(other.SignatureAlgorithm)
        && (SignatureValue ?? Array.Empty<byte>()).SequenceEqual(other.SignatureValue ?? Array.Empty<byte>());

    public override bool Equals(object? obj) => Equals(obj as DelegationAuthorization);

    public override int GetHashCode()
    {
        int h = Reason.GetHashCode();
        h = h * 31 + RequestedLifetime;
        h = h * 31 + Timestamp.GetHashCode();
        h = h * 31 + (Nonce?.Length ?? 0);
        h = h * 31 + SignatureAlgorithm.GetHashCode();
        return h;
    }
}