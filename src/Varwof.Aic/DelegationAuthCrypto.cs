using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Varwof.Aic;

/// <summary>
/// Crypto helpers shared between the core package and DelegationAuthTbs:
/// CurvePolicy-driven asymmetric signature defaults and DER wrapper types.
/// </summary>
public static class DelegationAuthCrypto
{
    /// <summary>CurvePolicy -> AlgorithmIdentifier (EC curve-based SHA-2, RSA PSS, Ed25519).</summary>
    public static AlgorithmIdentifier? SignatureFromCurvePolicy(int curvePolicy)
    {
        if (curvePolicy == (int)CurvePolicy.P256)
        {
            return SigAlgorithms.PickEcdsa(Oids.Sha256);
        }
        if (curvePolicy == (int)CurvePolicy.P384)
        {
            return SigAlgorithms.PickEcdsa(Oids.Sha384);
        }
        if (curvePolicy == (int)CurvePolicy.P521)
        {
            return SigAlgorithms.PickEcdsa(Oids.Sha512);
        }
        if (curvePolicy == (int)CurvePolicy.Ed25519)
        {
            return SigAlgorithms.Ed25519Algorithm();
        }
        if (curvePolicy == (int)CurvePolicy.Rsa3072)
        {
            return SigAlgorithms.RsaPssDefault();
        }
        if (curvePolicy == (int)CurvePolicy.Rsa2048)
        {
            return SigAlgorithms.RsaPssDefault();
        }
        return null;
    }

    /// <summary>
    /// Sign the TBS with the principal's private key, producing a DA whose
    /// reason/lifetime/timestamp/nonce mirror the TBS. The signature input is
    /// the DER encoding of the TBS.
    /// </summary>
    public static DelegationAuthorization Sign(DelegationAuthTbs tbs, AsymmetricKeyParameter key, DerObjectIdentifier sigOid)
    {
        if (tbs.Nonce is null)
        {
            throw new AicException("DelegationAuthCrypto: TBS nonce is required");
        }
        byte[] input = tbs.Encode();
        byte[] sig = ComputeSignature(sigOid, key, input);
        return new DelegationAuthorization(
            tbs.Reason,
            tbs.RequestedLifetime,
            tbs.Timestamp,
            tbs.Nonce,
            new AlgorithmIdentifier(sigOid),
            sig);
    }

    /// <summary>Convenience overload: pick the recommended algorithm for the key.</summary>
    public static DelegationAuthorization Sign(DelegationAuthTbs tbs, AsymmetricKeyParameter key)
    {
        return Sign(tbs, key, SigAlgorithms.ForKey(key)!);
    }

    public static byte[] ComputeSignature(DerObjectIdentifier sigOid, AsymmetricKeyParameter key, byte[] input)
        => SigAlgorithms.Sign(sigOid, key, input);

    /// <summary>
    /// Verify a DA against the TBS it claims to authorize: the TBS is re-encoded
    /// exactly (byte-identical DER) and checked against the recorded signature.
    /// </summary>
    public static bool Verify(DelegationAuthTbs tbs, DelegationAuthorization da, AsymmetricKeyParameter principalKey)
    {
        if (da is null || da.SignatureValue is null || da.SignatureAlgorithm is null || principalKey is null)
        {
            return false;
        }
        DerObjectIdentifier oid = da.SignatureAlgorithm.Oid;
        if (!SigAlgorithms.IsSupported(oid))
        {
            return false;
        }
        if (oid.Equals(Oids.Ed25519) && da.SignatureValue.Length != 64)
        {
            return false;
        }
        byte[] input = tbs.Encode();
        return SigAlgorithms.Verify(oid, principalKey, input, da.SignatureValue);
    }

    /// <summary>
    /// Verify the DA carried by an AIC, reconstructing the TBS from the AIC.
    /// Returns false when the AIC has no present DA or the signature does not
    /// verify.
    /// </summary>
    public static bool VerifyAic(Aic aic, AsymmetricKeyParameter principalKey)
    {
        DelegationAuthorization? da = aic.DelegationAuthorization;
        if (da is null || !da.IsPresent() || principalKey is null)
        {
            return false;
        }
        DelegationAuthTbs tbs = DelegationAuthTbs.FromAic(aic);
        return Verify(tbs, da, principalKey);
    }
}

public static class CurvePolicy
{
    public const int P256 = 0;
    public const int P384 = 1;
    public const int P521 = 2;
    public const int Secp256k1 = 3;
    public const int Ed25519 = 4;
    public const int Rsa2048 = 5;
    public const int Rsa3072 = 6;

    public static string Name(int policy) => policy switch
    {
        P256 => "P-256",
        P384 => "P-384",
        P521 => "P-521",
        Secp256k1 => "secp256k1",
        Ed25519 => "ed25519",
        Rsa2048 => "rsa-2048",
        Rsa3072 => "rsa-3072",
        _ => "unknown(" + policy + ")"
    };
}