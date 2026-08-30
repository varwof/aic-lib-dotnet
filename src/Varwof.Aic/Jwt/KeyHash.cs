using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// Key material and hash bindings for AIC-JWT (draft-wei-aic-jwt Section 9).
/// Mirrors Go types/aicjwt/keyhash.go: RFC 7638 JWK thumbprints, SPKI hashes,
/// JWK&lt;-&gt;public conversions and principal key lookup.
/// </summary>
public static class KeyHash
{
    /// <summary>hash_alg values implemented here. sha3-* and sm3 are not implemented.</summary>
    public static readonly Dictionary<string, int> SupportedHashAlgs = new()
    {
        ["sha-256"] = 32,
        ["sha-384"] = 48,
        ["sha-512"] = 64,
        ["jkt"] = 32
    };

    /// <summary>Minimal RFC 7517 public JWK supporting EC, RSA and OKP.</summary>
    public sealed class Jwk
    {
        public string? Kty { get; set; }
        public string? Crv { get; set; }
        public string? X { get; set; }
        public string? Y { get; set; }
        public string? N { get; set; }
        public string? E { get; set; }
    }

    /// <summary>Computes hash_alg(SPKI) over an X.509 SubjectPublicKeyInfo DER blob.</summary>
    public static string SpkiHash(byte[] spkiDer, string hashAlg)
    {
        DerObjectIdentifier oid = hashAlg switch
        {
            "sha-256" => Oids.Sha256,
            "sha-384" => Oids.Sha384,
            "sha-512" => Oids.Sha512,
            _ => throw new AicException("unsupported SPKI hash algorithm \"" + hashAlg + "\"")
        };
        return Jws.B64uEncode(HashAlgorithms.KeyHashFromSpki(oid, spkiDer));
    }

    /// <summary>Computes hash_alg(SPKI) directly from a public key (SPKI DER).</summary>
    public static string SpkiHashPub(byte[] spkiDer, string hashAlg) => SpkiHash(spkiDer, hashAlg);

    /// <summary>RFC 7638 JWK thumbprint for EC, RSA and OKP keys.</summary>
    public static string JwkThumbprint(Jwk j)
    {
        string canon;
        switch (j.Kty)
        {
            case "EC":
                canon = "{\"crv\":\"" + j.Crv + "\",\"kty\":\"EC\",\"x\":\"" + j.X + "\",\"y\":\"" + j.Y + "\"}";
                break;
            case "RSA":
                canon = "{\"e\":\"" + j.E + "\",\"kty\":\"RSA\",\"n\":\"" + j.N + "\"}";
                break;
            case "OKP":
                canon = "{\"crv\":\"" + j.Crv + "\",\"kty\":\"OKP\",\"x\":\"" + j.X + "\"}";
                break;
            default:
                throw new AicException("unsupported kty \"" + j.Kty + "\"");
        }
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(canon));
        return Jws.B64uEncode(hash);
    }

    /// <summary>Converts a public key (SPKI DER) to a minimal JWK.</summary>
    public static Jwk PublicKeyToJwk(byte[] spkiDer)
    {
        try
        {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(spkiDer));
            AsymmetricKeyParameter pub = PublicKeyFactory.CreateKey(spki);
            if (pub is ECPublicKeyParameters ec)
            {
                int bits = ec.Parameters.Curve.FieldSize;
                string crv = bits switch
                {
                    256 => "P-256",
                    384 => "P-384",
                    521 => "P-521",
                    _ => throw new AicException("unsupported curve")
                };
                int size = (bits + 7) / 8;
                byte[] xb = ToFixed(ec.Q.AffineXCoord.ToBigInteger(), size);
                byte[] yb = ToFixed(ec.Q.AffineYCoord.ToBigInteger(), size);
                return new Jwk
                {
                    Kty = "EC",
                    Crv = crv,
                    X = Jws.B64uEncode(xb),
                    Y = Jws.B64uEncode(yb)
                };
            }
            if (pub is RsaKeyParameters rsa)
            {
                return new Jwk
                {
                    Kty = "RSA",
                    N = Jws.B64uEncode(rsa.Modulus.ToByteArray()),
                    E = Jws.B64uEncode(rsa.Exponent.ToByteArray())
                };
            }
            if (spki.Algorithm.Algorithm.Equals(Oids.Ed25519))
            {
                var bitString = spki.PublicKey;
                byte[] raw = bitString.GetOctets();
                return new Jwk
                {
                    Kty = "OKP",
                    Crv = "Ed25519",
                    X = Jws.B64uEncode(raw)
                };
            }
            throw new AicException("unsupported public key type");
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("cannot export public key: " + ex.Message);
        }
    }

    /// <summary>Converts a minimal JWK back to a public key (SPKI DER).</summary>
    public static byte[] JwkToSpki(Jwk j)
    {
        try
        {
            switch (j.Kty)
            {
                case "EC":
                {
                    Org.BouncyCastle.Asn1.X9.X9ECParameters curve = j.Crv switch
                    {
                        "P-256" => Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1"),
                        "P-384" => Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp384r1"),
                        "P-521" => Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp521r1"),
                        _ => throw new AicException("unsupported curve \"" + j.Crv + "\"")
                    };
                    DerObjectIdentifier curveOid = j.Crv switch
                    {
                        "P-256" => new DerObjectIdentifier("1.2.840.10045.3.1.7"),
                        "P-384" => new DerObjectIdentifier("1.3.132.0.34"),
                        "P-521" => new DerObjectIdentifier("1.3.132.0.35"),
                        _ => throw new AicException("unsupported curve \"" + j.Crv + "\"")
                    };
                    byte[] xb = Jws.B64uDecode(j.X!);
                    byte[] yb = Jws.B64uDecode(j.Y!);
                    var point = curve.Curve.CreatePoint(new BigInteger(1, xb), new BigInteger(1, yb));
                    var domain = new ECNamedDomainParameters(curveOid, curve);
                    var pubKey = new ECPublicKeyParameters(point, domain);
                    return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey).GetDerEncoded();
                }
                case "RSA":
                {
                    var n = new BigInteger(1, Jws.B64uDecode(j.N!));
                    var e = new BigInteger(1, Jws.B64uDecode(j.E!));
                    var rsaPub = new RsaKeyParameters(false, n, e);
                    return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaPub).GetDerEncoded();
                }
                case "OKP":
                {
                    if (j.Crv != "Ed25519")
                    {
                        throw new AicException("unsupported OKP crv \"" + j.Crv + "\"");
                    }
                    byte[] xb = Jws.B64uDecode(j.X!);
                    var edPub = new Ed25519PublicKeyParameters(xb, 0);
                    return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(edPub).GetDerEncoded();
                }
                default:
                    throw new AicException("unsupported kty \"" + j.Kty + "\"");
            }
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("cannot import JWK: " + ex.Message);
        }
    }

    /// <summary>Computes the binding of a public key (SPKI DER) for the given
    /// hash_alg: "jkt" uses the RFC 7638 thumbprint, otherwise the SPKI hash.</summary>
    public static string KeyHashOf(byte[] spkiDer, string? hashAlg)
    {
        if (hashAlg == "jkt")
        {
            return JwkThumbprint(PublicKeyToJwk(spkiDer));
        }
        if (string.IsNullOrEmpty(hashAlg))
        {
            hashAlg = "sha-256";
        }
        return SpkiHash(spkiDer, hashAlg);
    }

    /// <summary>Optional credential bundle: X.509 cert DER list (PKI mode) or
    /// JSON dictionary of JWKs fetched online.</summary>
    public sealed class PrincipalKeyMaterial
    {
        public IReadOnlyList<byte[]>? X5c { get; init; }
        public IReadOnlyDictionary<string, byte[]>? JwkSpki { get; init; }

        /// <summary>Finds an SPKI whose binding matches the principal claim.</summary>
        public byte[] LookupByBinding(Claims.Principal p)
        {
            if (p.HashAlg == "jkt")
            {
                if (JwkSpki is not null)
                {
                    foreach (byte[] spki in JwkSpki.Values)
                    {
                        if (JwkThumbprint(PublicKeyToJwk(spki)) == p.KeyHash)
                        {
                            return spki;
                        }
                    }
                }
                throw new AicException("no JWK matches key_hash " + p.KeyHash);
            }
            string alg = string.IsNullOrEmpty(p.HashAlg) ? "sha-256" : p.HashAlg;
            if (X5c is not null)
            {
                foreach (byte[] cert in X5c)
                {
                    try
                    {
                        byte[] spki = Varwof.Aic.KeyHashUtil.SpkiDer(cert);
                        if (SpkiHash(spki, alg) == p.KeyHash)
                        {
                            return spki;
                        }
                    }
                    catch (AicException)
                    {
                        // skip malformed certs
                    }
                }
            }
            throw new AicException("no certificate matches key_hash " + p.KeyHash);
        }
    }

    /// <summary>Decodes a JWK JSON object into an SPKI.</summary>
    public static byte[] ParseJwk(byte[] raw)
    {
        try
        {
            Jwk? j = System.Text.Json.JsonSerializer.Deserialize<Jwk>(raw, JwtJson.WireOptions);
            if (j is null)
            {
                throw new AicException("invalid JWK: empty");
            }
            return JwkToSpki(j);
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("invalid JWK: " + ex.Message);
        }
    }

    private static byte[] ToFixed(BigInteger v, int size)
    {
        byte[] raw = v.ToByteArray();
        if (raw.Length == size)
        {
            return raw;
        }
        if (raw.Length == size + 1 && raw[0] == 0)
        {
            var trimmed = new byte[size];
            Array.Copy(raw, 1, trimmed, 0, size);
            return trimmed;
        }
        var outBytes = new byte[size];
        int src = 0;
        while (src < raw.Length - 1 && raw[src] == 0)
        {
            src++;
        }
        int count = raw.Length - src;
        if (count > 0)
        {
            Array.Copy(raw, src, outBytes, size - count, count);
        }
        return outBytes;
    }
}