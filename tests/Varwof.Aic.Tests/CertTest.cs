using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Varwof.Aic.Cert;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>Certificate construction and extension extraction round trips.</summary>
public class CertTest
{
    private static AsymmetricCipherKeyPair Ec()
    {
        X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), curve.Curve.FieldSize));
        return keyGen.GenerateKeyPair();
    }

    private static Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo Spki(AsymmetricKeyParameter pub)
        => Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);

    private static readonly DateTime Now = new(2026, 8, 18, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void PrincipalCertRoundTrip()
    {
        AsymmetricCipherKeyPair keys = Ec();
        PrincipalAuthorization pa = new(1,
            new List<Capability> { new("database", "query:SELECT") },
            new List<Capability>(), new DelegationPolicy(1, 8, 1, null), new List<ExtField>());
        X509Certificate holder = AicCertificateBuilder.BuildPrincipalCert(
            keys.Private, Spki(keys.Public), pa, new X509Name("CN=principal-zhangsan"),
            BigInteger.One, Now, Now.AddSeconds(3600));
        PrincipalAuthorization? parsed = AicCertificates.ParsePrincipalAuthorization(holder);
        Assert.Equal(pa.GrantIds(), parsed!.GrantIds());
        Assert.Equal(pa.DelegationPolicy, parsed.DelegationPolicy);
    }

    [Fact]
    public void AgentCertRoundTrip()
    {
        AsymmetricCipherKeyPair ca = Ec();
        AsymmetricCipherKeyPair agent = Ec();
        byte[] spkiCa = Spki(ca.Public).GetDerEncoded();
        byte[] hash = HashAlgorithms.KeyHashFromSpki(Oids.Sha256, spkiCa);
        PrincipalUid pu = new(1, "corp.com", "zhangsan", hash, null);
        DelegationAuthTbs tbs = new(1, "agent-109", pu,
            new Reason("http", "Need to query users"),
            new List<Capability> { new("http", "GET:/api/v1/users", new byte[] { 0x01 }) },
            DelegationMode.Authorized, new List<Capability>(), 3600, Now, new byte[32]);
        Aic aic = new(1, "agent-109", pu, tbs.Capabilities, DelegationMode.Authorized, new List<Capability>(),
            DelegationAuthCrypto.Sign(tbs, ca.Private), new List<ExtField>());

        X509Certificate holder = AicCertificateBuilder.BuildAgentCert(
            ca.Private, new X509Name("CN=varwof-ca"), Spki(agent.Public), aic,
            new X509Name("CN=agent-109"), BigInteger.ValueOf(42), Now, Now.AddSeconds(3600),
            "spiffe://varwof.com/agent/agent-109");
        Aic parsed = AicCertificates.ParseAic(holder);
        Assert.Equal(aic.AgentId, parsed.AgentId);
        Assert.Equal(aic.Principal(), parsed.Principal());
        Assert.Equal(aic.Capabilities, parsed.Capabilities);
        Assert.True(parsed.DelegationAuthorization!.IsPresent());
        Assert.Null(AicCertificates.ParsePrincipalAuthorization(holder));
    }
}
