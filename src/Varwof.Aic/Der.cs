using System;
using System.Globalization;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Varwof.Aic;

/// <summary>
/// Low-level ASN.1/DER helpers shared by the AIC model classes.
/// The encoding is byte-compatible with the Go reference implementation
/// (which always emits default fields, uses GeneralizedTime as
/// YYYYMMDDHHMMSSZ UTC and uses [0] EXPLICIT only where the draft requires it).
/// </summary>
public static class Der
{
    /// <summary>DER encoding of an INTEGER, as Go emits it (minimal encoding).</summary>
    public static DerInteger Integer(long v) => new(BigInteger.ValueOf(v));

    /// <summary>DER encoding of a UTF8String (Go uses UTF8String tag 12 for text).</summary>
    public static DerUtf8String Utf8(string s) => new(s);

    /// <summary>
    /// GeneralizedTime in the canonical YYYYMMDDHHMMSSZ UTC form that the Go
    /// implementation emits (sub-second precision is dropped).
    /// </summary>
    public static Asn1GeneralizedTime Generalized(DateTime t)
    {
        if (t.Kind != DateTimeKind.Utc)
        {
            t = t.ToUniversalTime();
        }
        // Truncate sub-second precision rounding down (toward -inf), matching Go's
        // Time.Truncate, so pre-epoch negative-tick times are handled consistently.
        long wholeSeconds = (long)Math.Floor((double)t.Ticks / TimeSpan.TicksPerSecond);
        t = new DateTime(wholeSeconds * TimeSpan.TicksPerSecond, DateTimeKind.Utc);
        return new Asn1GeneralizedTime(t.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z");
    }

    /// <summary>Empty optional [tag EXPLICIT] markers are omitted by the Go encoder.</summary>
    public static DerTaggedObject Explicit(int tag, Asn1Encodable value) => new(true, tag, value);

    /// <summary>Parse a timestamp encoded as GeneralizedTime back to a UTC DateTime.</summary>
    public static DateTime ToInstant(Asn1GeneralizedTime gt)
    {
        try
        {
            return gt.ToDateTime().ToUniversalTime();
        }
        catch (Exception ex)
        {
            throw new AicException("GeneralizedTime: unparsable timestamp", ex);
        }
    }

    /// <summary>Safely read an optional [tag] EXPLICIT wrapper from a sequence element.</summary>
    public static Asn1Object GetExplicit(Asn1Sequence seq, int index)
    {
        var t = Asn1TaggedObject.GetInstance(seq[index]);
        return (Asn1Object)t.GetBaseObject();
    }

    /// <summary>Read an optional [tagno EXPLICIT] element, returning null when the tag doesn't match.</summary>
    public static Asn1Object? OptionalTagContent(Asn1Encodable elem, int tagNo)
    {
        if (elem is Asn1TaggedObject t && t.TagNo == tagNo)
        {
            return (Asn1Object)t.GetBaseObject();
        }
        return null;
    }

    public static long IntValueLong(Asn1Encodable e) => DerInteger.GetInstance(e).Value.IntValue;

    public static int IntValue(Asn1Encodable e) => DerInteger.GetInstance(e).Value.IntValue;

    public static string StringValue(Asn1Encodable e) => DerUtf8String.GetInstance(e).GetString();

    public static byte[] OctetValue(Asn1Encodable e) => Asn1OctetString.GetInstance(e).GetOctets();

    public static DerObjectIdentifier OidValue(Asn1Encodable e) => DerObjectIdentifier.GetInstance(e);

    /// <summary>Best-effort string for a raw UTF8String that may be absent.</summary>
    public static string MaybeString(Asn1Encodable? nullable)
        => nullable is null ? "" : DerUtf8String.GetInstance(nullable).GetString();

    public static Asn1Sequence Seq(Asn1Encodable e) => Asn1Sequence.GetInstance(e);

    /// <summary>Convenience: build a SEQUENCE from encodables.</summary>
    public static DerSequence DerSequence(params Asn1Encodable[] elems) => new(elems);

    /// <summary>Convenience: encode an ASN.1 object to its DER bytes.</summary>
    public static byte[] DerEncode(Asn1Encodable e)
    {
        try
        {
            return e.ToAsn1Object().GetDerEncoded();
        }
        catch (Exception ex)
        {
            throw new AicException("DER encoding failed", ex);
        }
    }

    /// <summary>Parse DER bytes to an ASN.1 object (throws AicException on malformed input).</summary>
    public static Asn1Object FromBytes(byte[] der)
    {
        try
        {
            return Asn1Object.FromByteArray(der);
        }
        catch (Exception ex)
        {
            throw new AicException("bad DER", ex);
        }
    }
}