using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Structured ASN.1 principal identity (draft §5.2 / Go types.PrincipalUid).
/// DER: SEQUENCE { INTEGER version (DEFAULT 1), UTF8String realm,
///       UTF8String identifier, OCTET STRING keyHash,
///       [0] EXPLICIT AlgorithmIdentifier hashAlgo OPTIONAL }.
/// A null hashAlgo means "absent" and defaults to SHA-256.
///
/// Communication format: {realm}:{identifier}:{keyFingerprint} where the
/// fingerprint is base64url(raw, no pad) of keyHash.
/// </summary>
public sealed class PrincipalUid : IEquatable<PrincipalUid>
{
    public int Version { get; }
    public string Realm { get; }
    public string Identifier { get; }
    public byte[] KeyHash { get; }
    public AlgorithmIdentifier? HashAlgo { get; }

    public PrincipalUid(int version, string realm, string identifier, byte[] keyHash, AlgorithmIdentifier? hashAlgo)
    {
        Version = version;
        Realm = realm ?? throw new ArgumentNullException(nameof(realm));
        Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
        KeyHash = (byte[])(keyHash ?? throw new ArgumentNullException(nameof(keyHash))).Clone();
        HashAlgo = hashAlgo;
    }

    public PrincipalUid(string realm, string identifier, byte[] keyHash, AlgorithmIdentifier? hashAlgo)
        : this(1, realm, identifier, keyHash, hashAlgo) { }

    /// <summary>Effective hash algorithm OID (absent defaults to SHA-256).</summary>
    public DerObjectIdentifier HashAlgoOid()
        => HashAlgo?.Oid is null ? Oids.Sha256 : HashAlgo.Oid;

    /// <summary>Communication format {realm}:{identifier}:{keyFingerprint}.</summary>
    public string DisplayString()
    {
        string fp = JwsB64.UrlEncodeNoPad(KeyHash);
        return Realm + ":" + Identifier + ":" + fp;
    }

    public byte[] Encode()
    {
        var elems = new System.Collections.Generic.List<Asn1Encodable>
        {
            Der.Integer(Version),
            Der.Utf8(Realm),
            Der.Utf8(Identifier),
            new DerOctetString(KeyHash)
        };
        if (HashAlgo is not null)
        {
            elems.Add(Der.Explicit(0, Asn1Object.FromByteArray(HashAlgo.Encode())));
        }
        return Der.DerEncode(Der.DerSequence(elems.ToArray()));
    }

    public static PrincipalUid Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        if (seq.Count < 4 || seq.Count > 5)
        {
            throw new AicException("PrincipalUid: expected 4-5 elements, got " + seq.Count);
        }
        int version = Der.IntValue(seq[0]);
        string realm = Der.StringValue(seq[1]);
        string identifier = Der.StringValue(seq[2]);
        byte[] keyHash = Der.OctetValue(seq[3]);
        AlgorithmIdentifier? hashAlgo = null;
        if (seq.Count == 5)
        {
            Asn1Object? inner = Der.OptionalTagContent(seq[4], 0);
            if (inner is null)
            {
                throw new AicException("PrincipalUid: fifth element must be [0] EXPLICIT AlgorithmIdentifier");
            }
            hashAlgo = AlgorithmIdentifier.Decode(inner);
        }
        return new PrincipalUid(version, realm, identifier, keyHash, hashAlgo);
    }

    public static PrincipalUid Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

    /// <summary>
    /// Parse from communication format {realm}:{identifier}:{keyFingerprint},
    /// matching Go ParsePrincipalUid.
    /// </summary>
    public static PrincipalUid ParseDisplayString(string s)
    {
        string[] parts = s.Split(':', 3);
        if (parts.Length != 3)
        {
            throw new AicException("principal_uid: invalid format, expected {realm}:{identifier}:{keyFingerprint}");
        }
        if (parts[0].Length < 1 || parts[0].Length > 128)
        {
            throw new AicException("principal_uid: realm length " + parts[0].Length + ": must be 1-128");
        }
        if (parts[1].Length < 1 || parts[1].Length > 256)
        {
            throw new AicException("principal_uid: identifier length " + parts[1].Length + ": must be 1-256");
        }
        byte[] keyHash;
        try
        {
            keyHash = JwsB64.UrlDecode(parts[2]);
        }
        catch (Exception ex)
        {
            throw new AicException("principal_uid: invalid keyFingerprint base64url: " + ex.Message);
        }
        if (keyHash.Length < 1 || keyHash.Length > 64)
        {
            throw new AicException("principal_uid: keyHash length " + keyHash.Length + ": must be 1-64");
        }
        if (parts[0].Contains(':') || parts[1].Contains(':'))
        {
            throw new AicException("principal_uid: realm and identifier must not contain ':'");
        }
        return new PrincipalUid(1, parts[0], parts[1], keyHash, new AlgorithmIdentifier(Oids.Sha256));
    }

    public bool Equals(PrincipalUid? other) => other is not null
        && Version == other.Version
        && Realm == other.Realm
        && Identifier == other.Identifier
        && KeyHash.SequenceEqual(other.KeyHash)
        && Equals(HashAlgo, other.HashAlgo);

    public override bool Equals(object? obj) => Equals(obj as PrincipalUid);

    public override int GetHashCode()
    {
        int h = HashCode.Combine(Version, Realm, Identifier, HashAlgo);
        h = h * 31 + KeyHash.Length;
        return h;
    }

    public override string ToString() => DisplayString();
}

internal static class JwsB64
{
    public static string UrlEncodeNoPad(byte[] data) => Convert.ToBase64String(data)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] UrlDecode(string s)
    {
        string b = s.Replace('-', '+').Replace('_', '/');
        switch (b.Length % 4)
        {
            case 2: b += "=="; break;
            case 3: b += "="; break;
            case 1: throw new FormatException("bad base64url length");
        }
        return Convert.FromBase64String(b);
    }
}