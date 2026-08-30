using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Varwof.Aic.Cert;

/// <summary>
/// Extraction of the AIC and PrincipalAuthorization extensions from X.509
/// certificates. Port of Go ParseAIC / ParseUserPermissionExtension.
/// </summary>
public static class AicCertificates
{
    public static bool HasAicExtension(Org.BouncyCastle.X509.X509Certificate? holder)
        => holder is not null && holder.GetExtension(Oids.Aic) != null;

    /// <summary>
    /// Parse the AIC extension and validate its content. Combines ParseAic with
    /// AicValidator.Validate so callers cannot accept structurally-invalid AIC.
    /// </summary>
    public static Aic ParseAndValidateAic(Org.BouncyCastle.X509.X509Certificate holder)
    {
        Aic aic = ParseAic(holder);
        AicValidator.Validate(aic);
        return aic;
    }

    public static Aic ParseAndValidateAic(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        Aic aic = ParseAic(cert);
        AicValidator.Validate(aic);
        return aic;
    }

    /// <summary>
    /// Parse and validate the PrincipalAuthorization extension; returns null
    /// when absent. Combines ParsePrincipalAuthorization with
    /// PrincipalAuthorizationValidator.Validate.
    /// </summary>
    public static PrincipalAuthorization? ParseAndValidatePrincipalAuthorization(Org.BouncyCastle.X509.X509Certificate holder)
    {
        PrincipalAuthorization? pa = ParsePrincipalAuthorization(holder);
        if (pa is not null)
        {
            PrincipalAuthorizationValidator.Validate(pa);
        }
        return pa;
    }

    /// <summary>Parse the AIC extension value; throws when absent or malformed.</summary>
    public static Aic ParseAic(Org.BouncyCastle.X509.X509Certificate holder)
    {
        if (holder is null)
        {
            throw new AicException("aic: nil certificate");
        }
        X509Extension? ext = holder.GetExtension(Oids.Aic);
        if (ext is null)
        {
            throw new AicException("aic: AIC extension not present");
        }
        return Aic.Parse(((Asn1OctetString)ext.GetParsedValue()).GetOctets());
    }

    public static Aic ParseAic(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        byte[]? value = ExtensionValue(cert, Oids.Aic);
        if (value is null)
        {
            throw new AicException("aic: AIC extension not present");
        }
        return Aic.Parse(value);
    }

    /// <summary>Parse the PrincipalAuthorization extension; returns null when absent.</summary>
    public static PrincipalAuthorization? ParsePrincipalAuthorization(Org.BouncyCastle.X509.X509Certificate holder)
    {
        if (holder is null)
        {
            return null;
        }
        X509Extension? ext = holder.GetExtension(Oids.PrincipalAuthorization);
        if (ext is null)
        {
            return null;
        }
        return PrincipalAuthorization.Parse(((Asn1OctetString)ext.GetParsedValue()).GetOctets());
    }

    public static PrincipalAuthorization? ParsePrincipalAuthorization(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        byte[]? value = ExtensionValue(cert, Oids.PrincipalAuthorization);
        if (value is null)
        {
            return null;
        }
        return PrincipalAuthorization.Parse(value);
    }

    private static byte[]? ExtensionValue(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, DerObjectIdentifier oid)
    {
        if (cert is null)
        {
            return null;
        }
        try
        {
            var holder = new Org.BouncyCastle.X509.X509Certificate(cert.RawData);
            X509Extension? ext = holder.GetExtension(oid);
            return ext is null ? null : ((Asn1OctetString)ext.GetParsedValue()).GetOctets();
        }
        catch (System.Exception ex)
        {
            throw new AicException("cert: could not read extension " + oid, ex);
        }
    }
}