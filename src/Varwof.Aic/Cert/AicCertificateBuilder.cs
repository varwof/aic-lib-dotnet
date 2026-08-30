using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;

namespace Varwof.Aic.Cert;

/// <summary>
/// Convenience builders for the two certificate kinds in the AIC model:
/// principal certificates carrying a PrincipalAuthorization extension and agent
/// certificates carrying the (critical) AIC extension. Signer algorithm is
/// chosen from the issuer key type (ECDSA SHA-256/384/512 for EC curves,
/// RSA-PSS SHA-256 for RSA, Ed25519 for Ed keys). All X.509 handling is
/// Bouncy Castle.
/// </summary>
public static class AicCertificateBuilder
{
    /// <summary>BC content signer chosen from the key type.</summary>
    public static ISignatureFactory ContentSignerFor(AsymmetricKeyParameter key)
    {
        string alg;
        if (key is Ed25519PrivateKeyParameters)
        {
            alg = "Ed25519";
        }
        else if (key is ECPrivateKeyParameters ec)
        {
            int bits = ec.Parameters.Curve.FieldSize;
            alg = bits >= 521 ? "SHA512withECDSA" : bits >= 384 ? "SHA384withECDSA" : "SHA256withECDSA";
        }
        else if (key is RsaKeyParameters)
        {
            alg = "SHA256withRSAandMGF1";
        }
        else
        {
            throw new AicException("cert: unsupported signing key");
        }
        try
        {
            return new Asn1SignatureFactory(alg, key);
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: could not create content signer for " + alg, ex);
        }
    }

    /// <summary>
    /// Self-signed principal certificate exposing the given PrincipalAuthorization
    /// extension under the principal's own key.
    /// </summary>
    public static Org.BouncyCastle.X509.X509Certificate BuildPrincipalCert(
        AsymmetricKeyParameter principalKey,
        Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo principalSpki,
        PrincipalAuthorization pa,
        X509Name? subject,
        BigInteger serial,
        DateTime notBeforeUtc,
        DateTime notAfterUtc)
    {
        DateTime nb = notBeforeUtc.ToUniversalTime();
        DateTime na = notAfterUtc.ToUniversalTime();
        X509Name effectiveSubject = subject ?? new X509Name("CN=" + Convert.ToHexString(principalSpki.GetDerEncoded()));
        var b = new X509V3CertificateGenerator();
        b.SetSerialNumber(serial);
        b.SetIssuerDN(effectiveSubject);
        b.SetNotBefore(nb);
        b.SetNotAfter(na);
        b.SetSubjectDN(effectiveSubject);
        b.SetPublicKey(PublicKeyFactory.CreateKey(principalSpki));
        try
        {
            b.AddExtension(Oids.PrincipalAuthorization, false, new DerOctetString(pa.Encode()));
            b.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            b.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.DigitalSignature));
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: principal extension attach failed", ex);
        }
        try
        {
            return b.Generate(ContentSignerFor(principalKey));
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: principal cert build failed", ex);
        }
    }

    /// <summary>
    /// Issue an agent certificate from issuerKey for the agent key carrying the
    /// (critical) AIC extension and an optional SPIFFE SAN.
    /// </summary>
    public static Org.BouncyCastle.X509.X509Certificate BuildAgentCert(
        AsymmetricKeyParameter issuerKey,
        X509Name issuer,
        Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo agentSpki,
        Aic aic,
        X509Name? subject,
        BigInteger serial,
        DateTime notBeforeUtc,
        DateTime notAfterUtc,
        string? spiffeSan)
    {
        DateTime nb = notBeforeUtc.ToUniversalTime();
        DateTime na = notAfterUtc.ToUniversalTime();
        var b = new X509V3CertificateGenerator();
        b.SetSerialNumber(serial);
        b.SetIssuerDN(issuer ?? new X509Name("CN=varwof-ca"));
        b.SetNotBefore(nb);
        b.SetNotAfter(na);
        b.SetSubjectDN(subject ?? new X509Name("CN=" + aic.AgentId));
        b.SetPublicKey(PublicKeyFactory.CreateKey(agentSpki));
        try
        {
            b.AddExtension(Oids.Aic, true, new DerOctetString(aic.Encode()));
            b.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            b.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            if (!string.IsNullOrEmpty(spiffeSan))
            {
                b.AddExtension(X509Extensions.SubjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, spiffeSan)));
            }
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: agent extension attach failed", ex);
        }
        try
        {
            return b.Generate(ContentSignerFor(issuerKey));
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: agent cert build failed", ex);
        }
    }

    /// <summary>SubjectPublicKeyInfo (SPKI) DER bytes for a raw public key.</summary>
    public static Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo SpkiFromKey(AsymmetricKeyParameter key)
    {
        try
        {
            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key);
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: SPKI derivation failed", ex);
        }
    }
}
