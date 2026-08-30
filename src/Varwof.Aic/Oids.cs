using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// OID assignments for the Varwof AIC family (IANA PEN 1.3.6.1.4.1.66257).
/// Mirrors the canonical table in the Go reference implementation
/// (types/oid.go) and draft-wei-aic-identity-cert-00 section 4.1.
/// </summary>
public static class Oids
{
    /// <summary>id-varwof : 1.3.6.1.4.1.66257</summary>
    public static readonly DerObjectIdentifier Varwof = new("1.3.6.1.4.1.66257");

    // ---- AIC extension tree (identity & authorization core) ----
    /// <summary>AIC extension OID : 1.3.6.1.4.1.66257.1.1</summary>
    public static readonly DerObjectIdentifier Aic = Varwof.Branch("1.1");
    /// <summary>AgentIdentity sub-OID : 1.3.6.1.4.1.66257.1.1.1</summary>
    public static readonly DerObjectIdentifier AicAgentIdentity = Varwof.Branch("1.1.1");
    /// <summary>DelegationAuthorization sub-OID : 1.3.6.1.4.1.66257.1.1.2</summary>
    public static readonly DerObjectIdentifier AicDelegationAuthorization = Varwof.Branch("1.1.2");
    /// <summary>DelegationDepthControl : 1.3.6.1.4.1.66257.1.1.4</summary>
    public static readonly DerObjectIdentifier DelegationDepthControl = Varwof.Branch("1.1.4");
    /// <summary>chainDepth : 1.3.6.1.4.1.66257.1.1.4.1</summary>
    public static readonly DerObjectIdentifier DdcChainDepth = Varwof.Branch("1.1.4.1");
    /// <summary>maxDepth : 1.3.6.1.4.1.66257.1.1.4.2</summary>
    public static readonly DerObjectIdentifier DdcMaxDepth = Varwof.Branch("1.1.4.2");

    /// <summary>PrincipalAuthorization extension OID : 1.3.6.1.4.1.66257.1.2</summary>
    public static readonly DerObjectIdentifier PrincipalAuthorization = Varwof.Branch("1.2");
    /// <summary>Renewal token : 1.3.6.1.4.1.66257.1.6</summary>
    public static readonly DerObjectIdentifier RenewalToken = Varwof.Branch("1.6");

    // ---- 3.x certification extensions ----
    /// <summary>1.3.6.1.4.1.66257.3.1</summary>
    public static readonly DerObjectIdentifier MarketAccessId = Varwof.Branch("3.1");
    /// <summary>1.3.6.1.4.1.66257.3.2</summary>
    public static readonly DerObjectIdentifier TrustLevel = Varwof.Branch("3.2");
    /// <summary>1.3.6.1.4.1.66257.3.3</summary>
    public static readonly DerObjectIdentifier CrossBorder = Varwof.Branch("3.3");

    // ---- Signature algorithm OIDs ----
    /// <summary>1.2.840.10045.4.3.2 ecdsa-with-SHA256</summary>
    public static readonly DerObjectIdentifier EcdsaWithSha256 = new("1.2.840.10045.4.3.2");
    /// <summary>1.2.840.10045.4.3.3 ecdsa-with-SHA384</summary>
    public static readonly DerObjectIdentifier EcdsaWithSha384 = new("1.2.840.10045.4.3.3");
    /// <summary>1.2.840.10045.4.3.4 ecdsa-with-SHA512</summary>
    public static readonly DerObjectIdentifier EcdsaWithSha512 = new("1.2.840.10045.4.3.4");
    /// <summary>1.2.840.113549.1.1.11 sha256WithRSAEncryption</summary>
    public static readonly DerObjectIdentifier RsaWithSha256 = new("1.2.840.113549.1.1.11");
    /// <summary>1.2.840.113549.1.1.12 sha384WithRSAEncryption</summary>
    public static readonly DerObjectIdentifier RsaWithSha384 = new("1.2.840.113549.1.1.12");
    /// <summary>1.2.840.113549.1.1.13 sha512WithRSAEncryption</summary>
    public static readonly DerObjectIdentifier RsaWithSha512 = new("1.2.840.113549.1.1.13");
    /// <summary>1.2.840.113549.1.1.10 RSASSA-PSS</summary>
    public static readonly DerObjectIdentifier RsaPss = new("1.2.840.113549.1.1.10");
    /// <summary>1.3.101.112 Ed25519</summary>
    public static readonly DerObjectIdentifier Ed25519 = new("1.3.101.112");

    // ---- Hash algorithm OIDs ----
    /// <summary>2.16.840.1.101.3.4.2.1 SHA-256</summary>
    public static readonly DerObjectIdentifier Sha256 = new("2.16.840.1.101.3.4.2.1");
    /// <summary>2.16.840.1.101.3.4.2.2 SHA-384</summary>
    public static readonly DerObjectIdentifier Sha384 = new("2.16.840.1.101.3.4.2.2");
    /// <summary>2.16.840.1.101.3.4.2.3 SHA-512</summary>
    public static readonly DerObjectIdentifier Sha512 = new("2.16.840.1.101.3.4.2.3");
    /// <summary>2.16.840.1.101.3.4.2.8 SHA3-256</summary>
    public static readonly DerObjectIdentifier Sha3_256 = new("2.16.840.1.101.3.4.2.8");
    /// <summary>2.16.840.1.101.3.4.2.9 SHA3-384</summary>
    public static readonly DerObjectIdentifier Sha3_384 = new("2.16.840.1.101.3.4.2.9");
    /// <summary>2.16.840.1.101.3.4.2.10 SHA3-512</summary>
    public static readonly DerObjectIdentifier Sha3_512 = new("2.16.840.1.101.3.4.2.10");
    /// <summary>1.2.156.10197.1.401 SM3</summary>
    public static readonly DerObjectIdentifier Sm3 = new("1.2.156.10197.1.401");

    // ---- EC algorithm OIDs ----
    /// <summary>1.2.840.10045.2.1 id-ecPublicKey</summary>
    public static readonly DerObjectIdentifier EcPublicKey = new("1.2.840.10045.2.1");
    /// <summary>1.2.840.10045.3.1.7 prime256v1 (P-256)</summary>
    public static readonly DerObjectIdentifier Prime256v1 = new("1.2.840.10045.3.1.7");
    /// <summary>1.3.132.0.34 secp384r1 (P-384)</summary>
    public static readonly DerObjectIdentifier Secp384r1 = new("1.3.132.0.34");
    /// <summary>1.3.132.0.35 secp521r1 (P-521)</summary>
    public static readonly DerObjectIdentifier Secp521r1 = new("1.3.132.0.35");
    /// <summary>1.2.840.113549.1.1.1 rsaEncryption</summary>
    public static readonly DerObjectIdentifier RsaEncryption = new("1.2.840.113549.1.1.1");
}