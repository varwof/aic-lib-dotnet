using System;
using System.Collections.Generic;
using System.Net;
using Varwof.Aic.Jwt;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>
/// Cross-language conformance: a token generated and signed by the Go
/// reference implementation must validate end-to-end in this C# port,
/// including key-binding (SPKI hash), JWK thumbprint and signature checks.
/// </summary>
public class GoConformanceTest
{
    private static DateTime FromEpoch(long sec)
        => DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime;

    private static byte[] PubKey(string spkiB64) => Convert.FromBase64String(spkiB64);

    private static Constraints.RequestContext Ctx(long now, string ip)
        => new()
        {
            Now = FromEpoch(now),
            SourceIp = IPAddress.Parse(ip),
            ConcurrentCount = 1
        };

    private static Validator.VerifyOptions BaseOpts(byte[] principalSpki, byte[] caSpki, long now)
    {
        return new Validator.VerifyOptions
        {
            Now = FromEpoch(now),
            ExpectedIssuer = "https://ca.example.com/aic",
            ExpectedAudience = new List<string> { "https://gw.example.com" },
            IssuerSpki = new Dictionary<string, byte[]> { ["ca-2026-01"] = caSpki },
            PrincipalJwks = new Dictionary<string, byte[]> { ["principal-zhangsan-2026"] = principalSpki },
            PresenterSpki = principalSpki,
            NonceStore = NonceStore.NewMemNonceStore(),
            RequestContext = Ctx(now, "10.1.2.3")
        };
    }

    [Fact]
    public void GoTokenValidatesEndToEnd()
    {
        byte[] principalSpki = PubKey(TokenFixtures.PrincipalSpkiB64);
        byte[] caSpki = PubKey(TokenFixtures.CaSpkiB64);

        Assert.Equal(TokenFixtures.ExpectedKeyHash, KeyHash.SpkiHashPub(principalSpki, "sha-256"));
        Assert.Equal(TokenFixtures.ExpectedJkt, KeyHash.KeyHashOf(principalSpki, "jkt"));
        Assert.Equal(principalSpki, KeyHash.JwkToSpki(KeyHash.PublicKeyToJwk(principalSpki)));

        Validator.VerifyOptions opts = BaseOpts(principalSpki, caSpki, TokenFixtures.Iat + 60);
        opts.RequestCapability = new Claims.Capability
        {
            Scheme = "database",
            Id = "query:SELECT",
            Params = JwtJson.Parse("{\"max_rows\":50}")
        };
        opts.CapabilityPlugins = new Dictionary<string, Validator.CapabilityPlugin>
        {
            ["database"] = (req, _) =>
            {
                int rows = req.Params!["max_rows"]!.GetValue<int>();
                if (rows > 200)
                {
                    throw new AicException("max_rows exceeds budget");
                }
            }
        };

        Validator.Decision d = Validator.Validate(TokenFixtures.GoOuterToken, opts);
        Assert.True(d.Permit);
        Assert.Equal("agent:db-analyst-01", d.Actor);
    }

    [Fact]
    public void GoTokenFailsWhenConstraintIsViolated()
    {
        byte[] principalSpki = PubKey(TokenFixtures.PrincipalSpkiB64);
        byte[] caSpki = PubKey(TokenFixtures.CaSpkiB64);
        Validator.VerifyOptions opts = BaseOpts(principalSpki, caSpki, TokenFixtures.Iat + 60);
        opts.RequestContext = Ctx(TokenFixtures.Iat + 60, "192.168.9.9");
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(TokenFixtures.GoOuterToken, opts));
        Assert.Contains("step7", ex.Message);
    }

    [Fact]
    public void GoTokenExpiredRejected()
    {
        byte[] principalSpki = PubKey(TokenFixtures.PrincipalSpkiB64);
        byte[] caSpki = PubKey(TokenFixtures.CaSpkiB64);
        Validator.VerifyOptions opts = BaseOpts(principalSpki, caSpki, TokenFixtures.Iat + 4000);
        opts.RequestContext = Ctx(TokenFixtures.Iat + 4000, "10.1.2.3");
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(TokenFixtures.GoOuterToken, opts));
        Assert.Contains("step3", ex.Message);
        Assert.DoesNotContain("nonce", ex.Message);
    }
}
