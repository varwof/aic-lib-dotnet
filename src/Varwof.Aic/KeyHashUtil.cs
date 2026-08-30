using System;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// keyHash computation from SPKI DER bytes and certificates.
/// Mirrors Go KeyHashFromCertSPKI / KeyHashFromSPKI.
/// </summary>
public static class KeyHashUtil
{
    /// <summary>SPKI SubjectPublicKeyInfo DER bytes from a raw certificate (X.509 holder usable anywhere).</summary>
    public static byte[] SpkiDer(byte[] certDer)
    {
        try
        {
            var holder = new Org.BouncyCastle.X509.X509Certificate(certDer);
            return holder.SubjectPublicKeyInfo.GetDerEncoded();
        }
        catch (Exception ex)
        {
            throw new AicException("keyhash: could not extract SPKI from certificate", ex);
        }
    }

    public static byte[] KeyHashFromCert(DerObjectIdentifier algo, byte[] certDer)
        => HashAlgorithms.KeyHashFromSpki(algo, SpkiDer(certDer));
}