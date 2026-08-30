using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Varwof.Aic;

/// <summary>
/// Signature algorithm selection and raw (JOSE-style) signature verification
/// over binary payloads. Port of Go types/aic_sig.go; asymmetric defaults:
/// EC -> ECDSA with SHA-2 sized to the curve, RSA (KeyUsage keyEncipherment)
/// -> RSASSA-PSS (SHA-256, MGF1 SHA-256, salt 32), Ed25519 -> raw EdDSA.
/// </summary>
public static class SigAlgorithms
{
    public const string EcDsaSha256 = "ecdsa-sha256";
    public const string EcDsaSha384 = "ecdsa-sha384";
    public const string EcDsaSha512 = "ecdsa-sha512";
    public const string RsaSsaPssSha256 = "rsassa-pss-sha256";
    public const string RsaSsaPssSha384 = "rsassa-pss-sha384";
    public const string RsaSsaPssSha512 = "rsassa-pss-sha512";
    public const string Ed25519 = "ed25519";
    public const string HmacSha256 = "hmac-sha256";

    public static AlgorithmIdentifier? Raw(AsymmetricKeyParameter key)
    {
        if (key is Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)
        {
            return Ed25519Algorithm();
        }
        if (key is ECPublicKeyParameters ec)
        {
            int bits = ec.Parameters.Curve.FieldSize;
            DerObjectIdentifier? hash = bits switch
            {
                256 => Oids.Sha256,
                384 => Oids.Sha384,
                512 => Oids.Sha512,
                _ => null
            };
            if (hash is null)
            {
                return null;
            }
            return PickEcdsa(hash);
        }
        if (key is RsaKeyParameters)
        {
            return null; // asymmetric RSA default is handled via keyUsage below
        }
        return null;
    }

    public static bool IsSupported(DerObjectIdentifier oid)
        => oid.Equals(Oids.Sha256) || oid.Equals(Oids.Sha384) || oid.Equals(Oids.Sha512)
           || oid.Equals(Oids.EcdsaWithSha256) || oid.Equals(Oids.EcdsaWithSha384) || oid.Equals(Oids.EcdsaWithSha512)
           || oid.Equals(Oids.RsaWithSha256) || oid.Equals(Oids.RsaWithSha384) || oid.Equals(Oids.RsaWithSha512)
           || oid.Equals(Oids.RsaPss) || oid.Equals(Oids.Ed25519);

    /// <summary>Recommended signature OID for the given private key.</summary>
    public static DerObjectIdentifier? ForKey(AsymmetricKeyParameter key)
    {
        if (key is Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters)
        {
            return Oids.Ed25519;
        }
        if (key is ECPrivateKeyParameters ec)
        {
            return ec.Parameters.Curve.FieldSize switch
            {
                >= 521 => Oids.EcdsaWithSha512,
                >= 384 => Oids.EcdsaWithSha384,
                _ => Oids.EcdsaWithSha256
            };
        }
        if (key is RsaKeyParameters)
        {
            return Oids.RsaPss;
        }
        throw new AicException("signature: unsupported key type");
    }

    /// <summary>
    /// Sign a message with the algorithm identified by a signature OID,
    /// producing the wire form used by DelegationAuthorization (DER for
    /// ECDSA/RSA, raw Ed25519; PSS configured with SHA-256 salt 32).
    /// </summary>
    public static byte[] Sign(DerObjectIdentifier oid, AsymmetricKeyParameter key, byte[] message)
    {
        if (oid.Equals(Oids.Ed25519))
        {
            if (!(key is Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters))
            {
                throw new AicException("ed25519 requires an Ed25519 private key");
            }
            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }
        if (oid.Equals(Oids.RsaPss))
        {
            if (!(key is RsaKeyParameters))
            {
                throw new AicException("rsassa-pss requires an RSA private key");
            }
            var pss = new PssSigner(
                new Org.BouncyCastle.Crypto.Engines.RsaBlindedEngine(),
                new Sha256Digest(), 32);
            pss.Init(true, key);
            pss.BlockUpdate(message, 0, message.Length);
            return pss.GenerateSignature();
        }
        if (oid.Equals(Oids.RsaWithSha256) || oid.Equals(Oids.RsaWithSha384) || oid.Equals(Oids.RsaWithSha512))
        {
            if (!(key is RsaKeyParameters))
            {
                throw new AicException("rsa signature requires an RSA private key");
            }
            var rs = new RsaDigestSigner(DigestForOid(oid));
            rs.Init(true, key);
            rs.BlockUpdate(message, 0, message.Length);
            return rs.GenerateSignature();
        }
        if (oid.Equals(Oids.EcdsaWithSha256) || oid.Equals(Oids.EcdsaWithSha384) || oid.Equals(Oids.EcdsaWithSha512))
        {
            if (!(key is ECPrivateKeyParameters ec))
            {
                throw new AicException("ecdsa signature requires an EC private key");
            }
            string algName = oid.Equals(Oids.EcdsaWithSha256) ? "SHA256withECDSA" :
                             oid.Equals(Oids.EcdsaWithSha384) ? "SHA384withECDSA" : "SHA512withECDSA";
            var signer = SignerUtilities.GetSigner(algName);
            signer.Init(true, ec);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }
        throw new AicException("signature: unsupported algorithm OID " + oid.Id);
    }

    /// <summary>
    /// Verify a wire-form signature (DER for ECDSA/RSA, raw Ed25519, PSS
    /// SHA-256 salt 32) against a message using the OID-identified algorithm.
    /// </summary>
    public static bool Verify(DerObjectIdentifier oid, AsymmetricKeyParameter key, byte[] message, byte[] signature)
    {
        if (key is null || signature is null)
        {
            return false;
        }
        try
        {
            if (oid.Equals(Oids.Ed25519))
            {
                if (!(key is Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters) || signature.Length != 64)
                {
                    return false;
                }
                var signer = new Ed25519Signer();
                signer.Init(false, key);
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signature);
            }
            if (oid.Equals(Oids.RsaPss))
            {
                if (!(key is RsaKeyParameters))
                {
                    return false;
                }
                var pss = new PssSigner(
                    new Org.BouncyCastle.Crypto.Engines.RsaBlindedEngine(),
                    new Sha256Digest(), 32);
                pss.Init(false, key);
                pss.BlockUpdate(message, 0, message.Length);
                return pss.VerifySignature(signature);
            }
            if (oid.Equals(Oids.RsaWithSha256) || oid.Equals(Oids.RsaWithSha384) || oid.Equals(Oids.RsaWithSha512))
            {
                if (!(key is RsaKeyParameters))
                {
                    return false;
                }
                var rs = new RsaDigestSigner(DigestForOid(oid));
                rs.Init(false, key);
                rs.BlockUpdate(message, 0, message.Length);
                return rs.VerifySignature(signature);
            }
            if (oid.Equals(Oids.EcdsaWithSha256) || oid.Equals(Oids.EcdsaWithSha384) || oid.Equals(Oids.EcdsaWithSha512))
            {
                if (!(key is ECPublicKeyParameters) || signature.Length < 8)
                {
                    return false;
                }
                string algName = oid.Equals(Oids.EcdsaWithSha256) ? "SHA256withECDSA" :
                                 oid.Equals(Oids.EcdsaWithSha384) ? "SHA384withECDSA" : "SHA512withECDSA";
                var signer = SignerUtilities.GetSigner(algName);
                signer.Init(false, key);
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signature);
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static IDigest DigestForOid(DerObjectIdentifier oid)
    {
        if (oid.Equals(Oids.Sha384) || oid.Equals(Oids.EcdsaWithSha384) || oid.Equals(Oids.RsaWithSha384))
        {
            return new Sha384Digest();
        }
        if (oid.Equals(Oids.Sha512) || oid.Equals(Oids.EcdsaWithSha512) || oid.Equals(Oids.RsaWithSha512))
        {
            return new Sha512Digest();
        }
        if (oid.Equals(Oids.Sha256) || oid.Equals(Oids.EcdsaWithSha256) || oid.Equals(Oids.RsaWithSha256))
        {
            return new Sha256Digest();
        }
        throw new AicException("signature: unsupported algorithm OID " + oid.Id);
    }

    /// <summary>ECDSA algorithm name/params for a hash OID.</summary>
    public static AlgorithmIdentifier PickEcdsa(DerObjectIdentifier hash)
    {
        if (hash.Equals(Oids.Sha384))
        {
            return new AlgorithmIdentifier(Oids.EcdsaWithSha384);
        }
        if (hash.Equals(Oids.Sha512))
        {
            return new AlgorithmIdentifier(Oids.EcdsaWithSha512);
        }
        return new AlgorithmIdentifier(Oids.EcdsaWithSha256);
    }

    public static AlgorithmIdentifier? PickRsaPssHash(DerObjectIdentifier hash)
    {
        string? name = hash switch
        {
            _ when hash.Equals(Oids.Sha256) => RsaSsaPssSha256,
            _ when hash.Equals(Oids.Sha384) => RsaSsaPssSha384,
            _ when hash.Equals(Oids.Sha512) => RsaSsaPssSha512,
            _ => null
        };
        return name is null ? null : new AlgorithmIdentifier(hash);
    }

    public static AlgorithmIdentifier RsaPssDefault() => new(Oids.RsaPss);

    public static AlgorithmIdentifier Ed25519Algorithm() => new(Oids.Ed25519);

    // ---- raw signature verification over raw bytes ----

    /// <summary>
    /// Verify raw bytes with the given signature algorithm against an SPKI
    /// (SubjectPublicKeyInfo) or raw public key. For asymmetric algorithms this
    /// is the raw JOSE-style primitive (e.g. PSS with salt = digest length).
    /// </summary>
    public static bool VerifyBytes(string alg, byte[] data, byte[] sig, AsymmetricKeyParameter? pub)
    {
        if (pub is null)
        {
            return false;
        }
        return alg switch
        {
            HmacSha256 => throw new AicException("sig: hmac-sha256 requires a shared key"),
            Ed25519 => VerifyEd25519(pub, data, sig),
            _ when alg == EcDsaSha256 || alg == EcDsaSha384 || alg == EcDsaSha512 => VerifyEcdsa(alg, pub, data, sig),
            _ when alg.StartsWith("rsassa-pss-", StringComparison.Ordinal) => VerifyPss(alg, pub, data, sig),
            _ => throw new AicException("sig: unsupported algorithm \"" + alg + "\"")
        };
    }

    public static bool VerifyEcdsa(string alg, AsymmetricKeyParameter pub, byte[] data, byte[] sig)
    {
        int bits = alg switch
        {
            EcDsaSha256 => 256,
            EcDsaSha384 => 384,
            EcDsaSha512 => 512,
            _ => -1
        };
        if (!(pub is ECPublicKeyParameters ecPub))
        {
            return false;
        }
        // JOSE binds the alg to a specific curve: ES256->P-256, ES384->P-384,
        // ES512->P-521. Reject a key whose curve does not match the alg to
        // prevent algorithm-confusion (e.g. ES256 with a P-384 key).
        int expectedFieldBits = bits switch
        {
            256 => 256,
            384 => 384,
            512 => 521,
            _ => -1
        };
        int fieldSize = ecPub.Parameters.Curve.FieldSize;
        if (fieldSize != expectedFieldBits)
        {
            return false;
        }
        string algName = bits switch { 256 => "SHA256withECDSA", 384 => "SHA384withECDSA", 512 => "SHA512withECDSA", _ => "SHA256withECDSA" };
        var signer = SignerUtilities.GetSigner(algName);
        signer.Init(false, ecPub);
        signer.BlockUpdate(data, 0, data.Length);
        int size = Ecdsa.CoordBytes(fieldSize);
        if (sig.Length != size * 2)
        {
            return false;
        }
        byte[] derSig = Ecdsa.RsToDer(sig, fieldSize);
        return signer.VerifySignature(derSig);
    }

    private static bool VerifyPss(string alg, AsymmetricKeyParameter pub, byte[] data, byte[] sig)
    {
        if (!(pub is RsaKeyParameters rsa))
        {
            return false;
        }
        int hashLen = alg switch
        {
            RsaSsaPssSha256 => 32,
            RsaSsaPssSha384 => 48,
            RsaSsaPssSha512 => 64,
            _ => -1
        };
        string digestName = hashLen switch { 32 => "SHA-256", 48 => "SHA-384", 64 => "SHA-512", _ => "SHA-256" };
        var pss = new PssSigner(
            new Org.BouncyCastle.Crypto.Engines.RsaBlindedEngine(),
            DigestUtilities.GetDigest(digestName),
            hashLen);
        pss.Init(false, rsa);
        pss.BlockUpdate(data, 0, data.Length);
        return pss.VerifySignature(sig);
    }

    private static bool VerifyEd25519(AsymmetricKeyParameter pub, byte[] data, byte[] sig)
    {
        if (!(pub is Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters ed))
        {
            return false;
        }
        if (sig.Length != 64)
        {
            return false;
        }
        var signer = new Ed25519Signer();
        signer.Init(false, ed);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(sig);
    }

    private static byte[] Hash(IDigest d, byte[] input)
    {
        d.BlockUpdate(input, 0, input.Length);
        byte[] outBytes = new byte[d.GetDigestSize()];
        d.DoFinal(outBytes, 0);
        return outBytes;
    }

    /// <summary>Public key from a SubjectPublicKeyInfo DER blob.</summary>
    public static AsymmetricKeyParameter? PublicKeyFromSpki(byte[] spki)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(spki));
            return PublicKeyFactory.CreateKey(info);
        }
        catch
        {
            return null;
        }
    }
}
