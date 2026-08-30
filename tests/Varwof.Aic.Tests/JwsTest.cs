using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Varwof.Aic.Jwt;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>JWS compact serialization round trips and tamper rejection for every
/// implemented algorithm.</summary>
public class JwsTest
{
    private static readonly byte[] Header = Encoding.ASCII.GetBytes("{\"alg\":\"ES256\",\"typ\":\"aic+jwt\"}");
    private static readonly byte[] Payload = Encoding.ASCII.GetBytes("{\"sub\":\"agent-109\"}");

    private static AsymmetricCipherKeyPair EcKey(int bits)
    {
        string name = bits switch { 384 => "P-384", 521 => "P-521", _ => "P-256" };
        var curve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName(name);
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), curve.Curve.FieldSize));
        return keyGen.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair RsaKey(int bits)
    {
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), bits));
        return keyGen.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair EdKey()
    {
        var keyGen = new Ed25519KeyPairGenerator();
        keyGen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return keyGen.GenerateKeyPair();
    }

    private void RoundTrip(string alg, AsymmetricCipherKeyPair kp)
    {
        string t = Jws.SignCompact(Header, Payload, alg, kp.Private);
        byte[][] parts = Jws.ParseCompact(t);
        Assert.Equal(Header, parts[0]);
        Assert.Equal(Payload, parts[1]);
        Jws.VerifyCompact(t, alg, kp.Public);
        Assert.Throws<AicException>(() => Jws.VerifyCompact(t + "x", alg, kp.Public));
    }

    [Fact]
    public void Es256() => RoundTrip("ES256", EcKey(256));

    [Fact]
    public void Rs256() => RoundTrip("RS256", RsaKey(2048));

    [Fact]
    public void Ps256() => RoundTrip("PS256", RsaKey(2048));

    [Fact]
    public void Ps384() => RoundTrip("PS384", RsaKey(2048));

    [Fact]
    public void Ps512() => RoundTrip("PS512", RsaKey(2048));

    [Fact]
    public void EdDsa() => RoundTrip("EdDSA", EdKey());

    [Fact]
    public void B64uRoundTrip()
    {
        byte[] raw = { 0, 1, 2, 3, 0xff, 12, 64, 65, 66 };
        Assert.Equal(raw, Jws.B64uDecode(Jws.B64uEncode(raw)));
        Assert.Throws<AicException>(() => Jws.B64uDecode("not*valid!"));
    }

    [Fact]
    public void NotInAllowlistRejected()
    {
        AsymmetricCipherKeyPair kp = EcKey(256);
        Assert.Throws<AicException>(() => Jws.SignCompact(Header, Payload, "HS256", kp.Private));
        Assert.Throws<AicException>(() => Jws.SignCompact(Header, Payload, "ES384", kp.Private));
    }

    [Fact]
    public void MalformedCompactRejected()
    {
        Assert.Throws<AicException>(() => Jws.ParseCompact("a.b"));
        Assert.Throws<AicException>(() => Jws.ParseCompact("a.b.c.d"));
    }
}
