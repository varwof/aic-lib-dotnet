using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Varwof.Aic;

/// <summary>
/// ECDSA signature conversions between ASN.1 DER SEQUENCE{r,s} (X.509 /
/// DelegationAuthorization form) and the fixed-length r||s form used by JOSE
/// (ES256/384/512). Port of the conventions in Go's crypto/ecdsa usage.
/// </summary>
public static class Ecdsa
{
    /// <summary>Convert a DER ECDSA signature to fixed-size r||s.</summary>
    public static byte[] DerToRs(byte[] der, int fieldSize)
    {
        int size = CoordBytes(fieldSize);
        try
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(Der.FromBytes(der));
            if (seq.Count != 2)
            {
                throw new AicException("ecdsa: DER signature must contain exactly 2 integers");
            }
            BigInteger r = DerInteger.GetInstance(seq[0]).Value;
            BigInteger s = DerInteger.GetInstance(seq[1]).Value;
            byte[] outBytes = new byte[size * 2];
            ToFixed(r, size, outBytes, 0);
            ToFixed(s, size, outBytes, size);
            return outBytes;
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("ecdsa: invalid DER signature: " + ex.Message, ex);
        }
    }

    /// <summary>Convert a fixed-size r||s signature to DER.</summary>
    public static byte[] RsToDer(byte[] rs, int fieldSize)
    {
        int size = CoordBytes(fieldSize);
        if (rs is null || rs.Length != size * 2)
        {
            throw new AicException("ecdsa: raw signature length " + (rs?.Length ?? 0)
                + " must be " + (size * 2));
        }
        var r = new BigInteger(1, rs[0..size]);
        var s = new BigInteger(1, rs[size..(size * 2)]);
        return Der.DerEncode(new DerSequence(new DerInteger(r), new DerInteger(s)));
    }

    private static void ToFixed(BigInteger v, int size, byte[] outBytes, int offset)
    {
        byte[] bare = v.ToByteArrayUnsigned();
        if (bare.Length == size)
        {
            Array.Copy(bare, 0, outBytes, offset, size);
        }
        else if (bare.Length < size)
        {
            Array.Copy(bare, 0, outBytes, offset + (size - bare.Length), bare.Length);
        }
        else
        {
            // a leading zero sign byte may exceed size
            if (bare.Length == size + 1 && bare[0] == 0)
            {
                Array.Copy(bare, 1, outBytes, offset, size);
            }
            else
            {
                throw new AicException("ecdsa: r/s value longer than field size");
            }
        }
    }

    /// <summary>Fixed coord size (bytes) for a key whose field is "bits" wide.</summary>
    public static int CoordBytes(int fieldBits) => (fieldBits + 7) / 8;
}