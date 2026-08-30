using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>DelegationAuthorization signing/verification and cross-field checks.</summary>
public class DelegationAuthCryptoTest
{
    private static AsymmetricCipherKeyPair EcKeyPair()
    {
        X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), curve.Curve.FieldSize));
        return keyGen.GenerateKeyPair();
    }

    private static DelegationAuthTbs Tbs(byte[]? nonce)
    {
        PrincipalUid pu = new(1, "corp.com", "zhangsan", new byte[32], null);
        return new DelegationAuthTbs(1, "agent-109", pu,
            new Reason("http", "Need to query users"),
            new List<Capability> { new("http", "GET:/api/v1/users", new byte[] { 0x01 }) },
            DelegationMode.Authorized, new List<Capability>(), 3600,
            new DateTime(2026, 8, 18, 0, 0, 0, DateTimeKind.Utc), nonce);
    }

    private static DelegationAuthTbs Tbs() => Tbs(new byte[32]);

    [Fact]
    public void SignAndVerifyEcRoundTrip()
    {
        AsymmetricCipherKeyPair keys = EcKeyPair();
        DelegationAuthTbs tbs = Tbs();
        DelegationAuthorization da = DelegationAuthCrypto.Sign(tbs, keys.Private);
        Assert.True(da.IsPresent());
        Assert.True(SigAlgorithms.IsSupported(da.SignatureAlgorithm.Oid));
        Assert.True(DelegationAuthCrypto.Verify(tbs, da, keys.Public),
            "fresh signature must verify");
    }

    [Fact]
    public void VerifyRejectsTamperedTbs()
    {
        AsymmetricCipherKeyPair keys = EcKeyPair();
        DelegationAuthTbs tbs = Tbs();
        DelegationAuthorization da = DelegationAuthCrypto.Sign(tbs, keys.Private);

        DelegationAuthTbs changed = new(1, "agent-OTHER", tbs.PrincipalUid, tbs.Reason, tbs.Capabilities,
            tbs.DelegationMode, tbs.AuthorizationConstraints, tbs.RequestedLifetime, tbs.Timestamp, tbs.Nonce);
        Assert.False(DelegationAuthCrypto.Verify(changed, da, keys.Public));
        Assert.False(DelegationAuthCrypto.Verify(tbs, new DelegationAuthorization(
            da.Reason, da.RequestedLifetime, da.Timestamp, da.Nonce,
            da.SignatureAlgorithm, new byte[64]), keys.Public));
    }

    [Fact]
    public void SigningRequiresNonce()
    {
        DelegationAuthTbs noNonce = Tbs(null);
        Assert.Throws<AicException>(() => DelegationAuthCrypto.Sign(noNonce, EcKeyPair().Private));
    }

    [Fact]
    public void VerifyAicPipeline()
    {
        AsymmetricCipherKeyPair keys = EcKeyPair();
        byte[] spki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(keys.Public).GetDerEncoded();
        byte[] hash = HashAlgorithms.KeyHashFromSpki(Oids.Sha256, spki);
        PrincipalUid pu = new(1, "corp.com", "zhangsan", hash, null);
        DelegationAuthTbs tbs = new(1, "agent-109", pu,
            new Reason("http", "Need to query users"),
            new List<Capability> { new("http", "GET:/api/v1/users", new byte[] { 0x01 }) },
            DelegationMode.Authorized, new List<Capability>(), 3600,
            new DateTime(2026, 8, 18, 0, 0, 0, DateTimeKind.Utc), new byte[32]);

        Aic aic = new(1, "agent-109", pu, tbs.Capabilities, DelegationMode.Authorized, new List<Capability>(),
            DelegationAuthCrypto.Sign(tbs, keys.Private), new List<ExtField>());
        Assert.True(DelegationAuthCrypto.VerifyAic(aic, keys.Public));

        Aic evil = new(1, "agent-OTHER", aic.PrincipalUid, aic.Capabilities, aic.DelegationMode,
            aic.AuthorizationConstraints, aic.DelegationAuthorization, aic.Extensions);
        Assert.False(DelegationAuthCrypto.VerifyAic(evil, keys.Public));
    }

    [Fact]
    public void EcdsaDerRsConversion()
    {
        AsymmetricCipherKeyPair keys = EcKeyPair();
        DelegationAuthTbs tbs = Tbs();
        DelegationAuthorization da = DelegationAuthCrypto.Sign(tbs, keys.Private);

        int size = Ecdsa.CoordBytes(256);
        byte[] rs = Ecdsa.DerToRs(da.SignatureValue!, 256);
        Assert.True(rs.Length == size * 2);
        byte[] back = Ecdsa.RsToDer(rs, 256);
        Assert.Equal(da.SignatureValue, back);
    }
}
