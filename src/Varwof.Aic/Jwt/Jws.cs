using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// JWS compact serialization primitives (draft-wei-aic-jwt Section 4.5).
/// Mirrors Go types/aicjwt/jws.go. ECDSA signatures use the JOSE R||S
/// representation while DER is used in certificates, so conversions are
/// applied (Ecdsa.RsToDer / Ecdsa.DerToRs).
/// </summary>
public static class Jws
{
    /// <summary>Full JOSE algorithm allowlist.</summary>
    public static readonly HashSet<string> AllowedAlgs = new()
    {
        "ES256", "ES384", "ES512",
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512", "EdDSA"
    };

    /// <summary>Algorithms actually implemented here.</summary>
    public static readonly HashSet<string> ImplementedAlgs = new()
    {
        "ES256", "RS256", "PS256", "PS384", "PS512", "EdDSA"
    };

    public static string B64uEncode(byte[] bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        b64 = b64.TrimEnd('=');
        b64 = b64.Replace('+', '-').Replace('/', '_');
        return b64;
    }

    public static byte[] B64uDecode(string s)
    {
        if (s is null)
        {
            throw new AicException("bad base64url: nil input");
        }
        if (s.Length % 4 == 1)
        {
            throw new AicException("bad base64url: invalid length");
        }
        foreach (char c in s)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok)
            {
                throw new AicException("bad base64url: invalid character '" + c + "'");
            }
        }
        try
        {
            string b64 = s.Replace('-', '+').Replace('_', '/');
            switch (b64.Length % 4)
            {
                case 2:
                    b64 += "==";
                    break;
                case 3:
                    b64 += "=";
                    break;
            }
            return Convert.FromBase64String(b64);
        }
        catch (Exception ex)
        {
            throw new AicException("bad base64url: " + ex.Message);
        }
    }

    public static string SignCompact(byte[] header, byte[] payload, string alg, AsymmetricKeyParameter key)
    {
        if (!AllowedAlgs.Contains(alg))
        {
            throw new AicException("algorithm \"" + alg + "\" not in AIC-JWT allowlist");
        }
        if (!ImplementedAlgs.Contains(alg))
        {
            throw new AicException("algorithm \"" + alg + "\" recognized but not implemented");
        }
        string eh = B64uEncode(header);
        string ep = B64uEncode(payload);
        string signingInput = eh + "." + ep;
        byte[] sig = SignBytes(alg, Encoding.ASCII.GetBytes(signingInput), key);
        return signingInput + "." + B64uEncode(sig);
    }

    public static byte[][] ParseCompact(string token)
    {
        string[] parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new AicException("malformed JWS compact serialization");
        }
        return new[] { B64uDecode(parts[0]), B64uDecode(parts[1]), B64uDecode(parts[2]) };
    }

    public static void VerifyCompact(string token, string alg, AsymmetricKeyParameter pub)
    {
        string[] parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new AicException("malformed JWS compact serialization");
        }
        byte[] sig = B64uDecode(parts[2]);
        byte[] input = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        try
        {
            if (!VerifyBytes(alg, input, sig, pub))
            {
                throw new AicException("JWS signature verification failed");
            }
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("JWS signature verification failed: " + ex.Message);
        }
    }

    public static byte[] SignBytes(string alg, byte[] input, AsymmetricKeyParameter key)
    {
        return alg switch
        {
            "ES256" => SignEs(input, key, 256),
            "RS256" => SignPkcs1(input, key, new Sha256Digest()),
            "PS256" => SignPss(input, key, new Sha256Digest(), 32),
            "PS384" => SignPss(input, key, new Sha384Digest(), 48),
            "PS512" => SignPss(input, key, new Sha512Digest(), 64),
            "EdDSA" => SignEdDsa(input, key),
            _ => throw new AicException("algorithm \"" + alg + "\" not supported")
        };
    }

    public static bool VerifyBytes(string alg, byte[] input, byte[] sig, AsymmetricKeyParameter pub)
    {
        return alg switch
        {
            "ES256" => VerifyEs(input, sig, pub, 256),
            "RS256" => VerifyPkcs1(input, sig, pub, new Sha256Digest()),
            "PS256" => VerifyPss(input, sig, pub, new Sha256Digest(), 32),
            "PS384" => VerifyPss(input, sig, pub, new Sha384Digest(), 48),
            "PS512" => VerifyPss(input, sig, pub, new Sha512Digest(), 64),
            "EdDSA" => VerifyEdDsa(input, sig, pub),
            _ => throw new AicException("algorithm \"" + alg + "\" not supported")
        };
    }

    private static byte[] SignEs(byte[] input, AsymmetricKeyParameter key, int bits)
    {
        if (!(key is ECPrivateKeyParameters ec))
        {
            throw new AicException("ES256 requires an EC private key");
        }
        if (ec.Parameters.Curve.FieldSize != bits)
        {
            throw new AicException("ES256 requires a P-256 key");
        }
        string algName = bits switch { 256 => "SHA256withECDSA", 384 => "SHA384withECDSA", 512 => "SHA512withECDSA", _ => "SHA256withECDSA" };
        var signer = SignerUtilities.GetSigner(algName);
        signer.Init(true, ec);
        signer.BlockUpdate(input, 0, input.Length);
        byte[] sig = signer.GenerateSignature();
        // Convert DER signature to JOSE R||S format
        Asn1Sequence seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(sig));
        var r = DerInteger.GetInstance(seq[0]).PositiveValue;
        var s = DerInteger.GetInstance(seq[1]).PositiveValue;
        int size = Ecdsa.CoordBytes(bits);
        byte[] outBytes = new byte[size * 2];
        WriteFixed(r, size, outBytes, 0);
        WriteFixed(s, size, outBytes, size);
        return outBytes;
    }

    private static bool VerifyEs(byte[] input, byte[] sig, AsymmetricKeyParameter pub, int bits)
    {
        if (!(pub is ECPublicKeyParameters ec))
        {
            return false;
        }
        int size = Ecdsa.CoordBytes(bits);
        if (sig.Length != 2 * size)
        {
            throw new AicException("ES256 signature length mismatch");
        }
        byte[] der = Ecdsa.RsToDer(sig, bits);
        string algName = bits switch { 256 => "SHA256withECDSA", 384 => "SHA384withECDSA", 512 => "SHA512withECDSA", _ => "SHA256withECDSA" };
        var signer = SignerUtilities.GetSigner(algName);
        signer.Init(false, ec);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.VerifySignature(der);
    }

    private static byte[] SignPkcs1(byte[] input, AsymmetricKeyParameter key, IDigest digest)
    {
        if (!(key is RsaKeyParameters))
        {
            throw new AicException("RS256 requires an RSA private key");
        }
        var signer = new RsaDigestSigner(digest);
        signer.Init(true, key);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    private static bool VerifyPkcs1(byte[] input, byte[] sig, AsymmetricKeyParameter pub, IDigest digest)
    {
        if (!(pub is RsaKeyParameters))
        {
            return false;
        }
        var signer = new RsaDigestSigner(digest);
        signer.Init(false, pub);
        signer.BlockUpdate(input, 0, input.Length);
        bool ok = signer.VerifySignature(sig);
        if (!ok)
        {
            throw new AicException("RS256 signature verification failed");
        }
        return true;
    }

    private static byte[] SignPss(byte[] input, AsymmetricKeyParameter key, IDigest digest, int saltLen)
    {
        if (!(key is RsaKeyParameters))
        {
            throw new AicException("PSS requires an RSA private key");
        }
        var signer = new PssSigner(new Org.BouncyCastle.Crypto.Engines.RsaBlindedEngine(), digest, saltLen);
        signer.Init(true, key);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    private static bool VerifyPss(byte[] input, byte[] sig, AsymmetricKeyParameter pub, IDigest digest, int saltLen)
    {
        if (!(pub is RsaKeyParameters))
        {
            return false;
        }
        var signer = new PssSigner(new Org.BouncyCastle.Crypto.Engines.RsaBlindedEngine(), digest, saltLen);
        signer.Init(false, pub);
        signer.BlockUpdate(input, 0, input.Length);
        bool ok = signer.VerifySignature(sig);
        if (!ok)
        {
            throw new AicException("PSS signature verification failed");
        }
        return true;
    }

    private static byte[] SignEdDsa(byte[] input, AsymmetricKeyParameter key)
    {
        if (!(key is Ed25519PrivateKeyParameters))
        {
            throw new AicException("EdDSA requires an Ed25519 private key");
        }
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    private static bool VerifyEdDsa(byte[] input, byte[] sig, AsymmetricKeyParameter pub)
    {
        if (!(pub is Ed25519PublicKeyParameters))
        {
            return false;
        }
        var signer = new Ed25519Signer();
        signer.Init(false, pub);
        signer.BlockUpdate(input, 0, input.Length);
        bool ok = signer.VerifySignature(sig);
        if (!ok)
        {
            throw new AicException("EdDSA signature verification failed");
        }
        return true;
    }

    private static byte[] Hash(IDigest d, byte[] input)
    {
        d.BlockUpdate(input, 0, input.Length);
        byte[] outBytes = new byte[d.GetDigestSize()];
        d.DoFinal(outBytes, 0);
        return outBytes;
    }

    private static void WriteFixed(BigInteger v, int size, byte[] outBytes, int offset)
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
            throw new AicException("jws: r/s value longer than field size");
        }
    }
}
