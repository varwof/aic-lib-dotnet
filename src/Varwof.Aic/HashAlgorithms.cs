using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Varwof.Aic;

/// <summary>
/// Hash algorithm name <-> OID <-> output-length mappings, and SPKI keyHash
/// computation. Port of Go types/hash.go (SHA-2/SHA-3 family; SM3 OID is
/// recognized for naming but computation is delegated to the caller).
/// </summary>
public static class HashAlgorithms
{
    private static readonly Dictionary<string, DerObjectIdentifier> NameToOid = new()
    {
        ["sha256"] = Oids.Sha256,
        ["sha384"] = Oids.Sha384,
        ["sha512"] = Oids.Sha512,
        ["sha3-256"] = Oids.Sha3_256,
        ["sha3-384"] = Oids.Sha3_384,
        ["sha3-512"] = Oids.Sha3_512
    };

    private static readonly Dictionary<string, int> OutputLen = new()
    {
        ["sha256"] = 32,
        ["sha384"] = 48,
        ["sha512"] = 64,
        ["sha3-256"] = 32,
        ["sha3-384"] = 48,
        ["sha3-512"] = 64
    };

    public static DerObjectIdentifier? OidForName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return null;
        }
        return NameToOid.TryGetValue(name.ToLowerInvariant(), out var oid) ? oid : null;
    }

    /// <summary>Canonical name for a hash OID; empty string when unknown.</summary>
    public static string NameForOid(DerObjectIdentifier oid)
    {
        if (oid is null)
        {
            return "";
        }
        foreach (KeyValuePair<string, DerObjectIdentifier> e in NameToOid)
        {
            if (e.Value.Equals(oid))
            {
                return e.Key;
            }
        }
        return "";
    }

    public static int? OutputLength(DerObjectIdentifier oid)
    {
        string name = NameForOid(oid);
        return name.Length == 0 ? null : OutputLen[name];
    }

    /// <summary>Parse a name to OID; empty input yields null (like Go's nil for empty).</summary>
    public static DerObjectIdentifier? Parse(string? s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return null;
        }
        DerObjectIdentifier? oid = OidForName(s);
        if (oid is null)
        {
            throw new AicException("hash_algo: unsupported algorithm \"" + s
                + "\", supported: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512");
        }
        return oid;
    }

    public static DerObjectIdentifier DefaultOid() => Oids.Sha256;

    /// <summary>SPKI DER digest (keyHash) computed with the given hash OID.</summary>
    public static byte[] KeyHashFromSpki(DerObjectIdentifier algo, byte[] spkiDer)
    {
        string name = NameForOid(algo);
        if (name.Length == 0)
        {
            throw new AicException("keyhash: unsupported hashAlgo " + algo + " (requires external dependency)");
        }
        IDigest d = DigestFor(name);
        d.BlockUpdate(spkiDer, 0, spkiDer.Length);
        byte[] outBytes = new byte[d.GetDigestSize()];
        d.DoFinal(outBytes, 0);
        return outBytes;
    }

    internal static IDigest DigestFor(string name) => name switch
    {
        "sha256" => new Sha256Digest(),
        "sha384" => new Sha384Digest(),
        "sha512" => new Sha512Digest(),
        "sha3-256" => new Sha3Digest(256),
        "sha3-384" => new Sha3Digest(384),
        "sha3-512" => new Sha3Digest(512),
        _ => throw new AicException("keyhash: no digest for \"" + name + "\"")
    };
}