using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Varwof.Aic.Jwt;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>End-to-end validation pipeline tests.</summary>
public class JwtValidatorTest
{
    private const long Iat = 1755500000L;
    private const string AgentId = "agent:db-analyst-01";
    private const string Realm = "corp.com";
    private const string PrincipalId = "zhangsan";
    private const string Issuer = "https://ca.example.com/aic";
    private const string Audience = "https://gw.example.com";

    private static DateTime FromEpoch(long sec)
        => DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime;

    private sealed class Pair
    {
        public AsymmetricCipherKeyPair Principal = null!;
        public AsymmetricCipherKeyPair Issuer = null!;
        public byte[] PrincipalSpki = null!;
        public byte[] IssuerSpki = null!;
        public string KeyHash = null!;
        public string Jkt = null!;
        public string Nonce = null!;
        public string DaToken = null!;
        public string OuterToken = null!;
    }

    private static Claims.Capability CapDatabase(long maxRows)
        => new() { Scheme = "database", Id = "query:SELECT", Params = JwtJson.Parse("{\"max_rows\":" + maxRows + "}") };

    private static byte[] Serialize(object o) => JsonSerializer.SerializeToUtf8Bytes(o, JwtJson.WireOptions);

    private static AsymmetricCipherKeyPair Ec()
    {
        X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), curve.Curve.FieldSize));
        return keyGen.GenerateKeyPair();
    }

    private static Pair Build()
    {
        Pair p = new();
        p.Principal = Ec();
        p.Issuer = Ec();
        p.PrincipalSpki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(p.Principal.Public).GetDerEncoded();
        p.IssuerSpki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(p.Issuer.Public).GetDerEncoded();
        p.KeyHash = KeyHash.SpkiHashPub(p.PrincipalSpki, "sha-256");
        p.Jkt = KeyHash.KeyHashOf(p.PrincipalSpki, "jkt");
        byte[] n = new byte[32];
        new SecureRandom().NextBytes(n);
        p.Nonce = Jws.B64uEncode(n);

        Claims.Header daHdr = new() { Alg = "ES256", Typ = Validator.TypDa, Kid = "principal-1" };
        Claims.DaClaims da = new()
        {
            Ver = 1,
            AgentId = AgentId,
            Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
            Reason = new Claims.Reason { Code = "DATA_ANALYSIS", Desc = "Scheduled production data analysis window" },
            Capabilities = new List<Claims.Capability> { CapDatabase(100) },
            DelegationMode = Validator.ModeAuthorized,
            Constraints = new List<Claims.Capability>
            {
                new() { Scheme = "varwof/constraint-v1", Id = "allowed-cidr", Params = JwtJson.Parse("[\"10.0.0.0/8\"]") }
            },
            RequestedLifetime = 3600,
            Ts = Iat,
            Nonce = p.Nonce
        };
        p.DaToken = Jws.SignCompact(Serialize(daHdr), Serialize(da), "ES256", p.Principal.Private);

        Claims.Header outerHdr = new() { Alg = "ES256", Typ = Validator.TypOuter, Kid = "ca-2026-01" };
        Claims.OuterClaims outer = new()
        {
            Iss = Issuer,
            Sub = AgentId,
            Aud = new Claims.Audience(new List<string> { Audience }),
            Iat = Iat,
            Exp = Iat + 3600,
            Jti = p.Nonce,
            Cnf = new Claims.Cnf { Jkt = p.Jkt },
            Aic = new Claims.AicClaims
            {
                Ver = 1,
                Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
                DelegationMode = Validator.ModeAuthorized,
                Capabilities = new List<Claims.Capability> { CapDatabase(100) },
                ChainDepth = 0,
                MaxDepth = 1,
                Constraints = new List<Claims.Capability>
                {
                    new() { Scheme = "varwof/constraint-v1", Id = "allowed-cidr", Params = JwtJson.Parse("[\"10.0.0.0/8\"]") }
                }
            },
            Da = p.DaToken
        };
        p.OuterToken = Jws.SignCompact(Serialize(outerHdr), Serialize(outer), "ES256", p.Issuer.Private);
        return p;
    }

    private static Validator.VerifyOptions FullOpts(Pair p, long now)
    {
        Validator.VerifyOptions opts = new()
        {
            Now = FromEpoch(now),
            ExpectedIssuer = Issuer,
            ExpectedAudience = new List<string> { Audience },
            IssuerSpki = new Dictionary<string, byte[]> { ["ca-2026-01"] = p.IssuerSpki },
            PrincipalJwks = new Dictionary<string, byte[]> { ["principal-1"] = p.PrincipalSpki },
            PresenterSpki = p.PrincipalSpki,
            NonceStore = NonceStore.NewMemNonceStore(),
            RequestContext = Ctx(now, "10.1.2.3", 1),
            RequestCapability = CapDatabase(50),
            CapabilityPlugins = new Dictionary<string, Validator.CapabilityPlugin>
            {
                ["database"] = (req, _) =>
                {
                    int rows = req.Params!["max_rows"]!.GetValue<int>();
                    if (rows > 200)
                    {
                        throw new AicException("max_rows exceeds budget");
                    }
                }
            }
        };
        return opts;
    }

    private static Constraints.RequestContext Ctx(long now, string ip, int concurrent)
        => new()
        {
            Now = FromEpoch(now),
            SourceIp = IPAddress.Parse(ip),
            ConcurrentCount = concurrent
        };

    [Fact]
    public void ValidTokenPermits()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        Validator.Decision d = Validator.Validate(p.OuterToken, opts);
        Assert.True(d.Permit);
        Assert.Equal(AgentId, d.Actor);
        Assert.Equal(PrincipalId, d.Principal);
        Assert.Single(d.Capabilities!);
        Validator.Validate(p.OuterToken, FullOpts(p, Iat + 61));
    }

    [Fact]
    public void ExpiredTokenRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 7200);
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("expired", ex.Message);
    }

    [Fact]
    public void TamperedSignatureRejected()
    {
        Pair p = Build();
        string[] seg = p.OuterToken.Split('.');
        string bad = seg[0] + "." + seg[1] + ".BADSIG";
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(bad, FullOpts(p, Iat + 60)));
        Assert.Contains("signature invalid", ex.Message);
    }

    [Fact]
    public void UnknownIssuerKidRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        opts.IssuerSpki = new Dictionary<string, byte[]> { ["other-kid"] = p.IssuerSpki };
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("unknown issuer kid", ex.Message);
    }

    [Fact]
    public void NoneAlgorithmRejected()
    {
        Pair p = Build();
        Claims.Header h = new() { Alg = "none", Typ = Validator.TypOuter, Kid = "ca-2026-01" };
        string tok = Jws.SignCompact(Serialize(h), Serialize(new Claims.OuterClaims()), "ES256", p.Issuer.Private);
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(tok, FullOpts(p, Iat + 60)));
        Assert.Contains("none", ex.Message);
    }

    [Fact]
    public void WrongAlgorithmRejected()
    {
        Claims.Header h = new() { Alg = "HS256", Typ = Validator.TypOuter, Kid = "ca-2026-01" };
        Assert.Throws<AicException>(() => Jws.SignCompact(Serialize(h), System.Text.Encoding.UTF8.GetBytes("{}"), "HS256", null!));
    }

    [Fact]
    public void DuplicateKeysRejected()
    {
        byte[] hb = System.Text.Encoding.UTF8.GetBytes("{\"alg\":\"ES256\",\"alg\":\"ES256\",\"typ\":\"aic+jwt\",\"kid\":\"k\"}");
        Assert.True(JwtJson.HasDuplicateKeys(hb));
        Assert.True(JwtJson.HasDuplicateKeys(System.Text.Encoding.UTF8.GetBytes("{\"a\":{\"b\":1,\"b\":2}}")));
        Assert.True(JwtJson.HasDuplicateKeys(System.Text.Encoding.UTF8.GetBytes("{\"a\":[{\"c\":1,\"c\":2}]}")));
        Assert.False(JwtJson.HasDuplicateKeys(System.Text.Encoding.UTF8.GetBytes("{\"a\":[{\"c\":1}],\"b\":{\"d\":2}}")));
    }

    [Fact]
    public void NonceReuseRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        Validator.Validate(p.OuterToken, opts);
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("nonce", ex.Message);
    }

    [Fact]
    public void CapabilityNotAllowedRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        opts.RequestCapability = new Claims.Capability { Scheme = "database", Id = "query:DELETE" };
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("step9", ex.Message);
    }

    [Fact]
    public void UnknownSchemeFailClosed()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        opts.RequestCapability = CapDatabase(50);
        opts.CapabilityPlugins = new Dictionary<string, Validator.CapabilityPlugin>();
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("fail-closed", ex.Message);
    }

    [Fact]
    public void ConstraintViolatedRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        opts.RequestContext = Ctx(Iat + 60, "192.168.0.9", 1);
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.True(ex.Message.Contains("step7") || ex.Message.Contains("allowed-cidr"), ex.Message);
    }

    [Fact]
    public void PresenterKeyMismatchRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        opts.PresenterSpki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(Ec().Public).GetDerEncoded();
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("cnf", ex.Message);
    }

    [Fact]
    public void AudienceConfusionRejected()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        opts.ExpectedAudience = new List<string> { "https://evil.example.com" };
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(p.OuterToken, opts));
        Assert.Contains("audience confusion", ex.Message);
    }

    [Fact]
    public void RepresentativeRequiresDa()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);
        Claims.Header h = new() { Alg = "ES256", Typ = Validator.TypOuter, Kid = "ca-2026-01" };
        Claims.OuterClaims outer = new()
        {
            Iss = Issuer,
            Sub = AgentId,
            Aud = new Claims.Audience(new List<string> { Audience }),
            Iat = Iat,
            Exp = Iat + 3600,
            Jti = p.Nonce,
            Cnf = new Claims.Cnf { Jkt = p.Jkt },
            Aic = new Claims.AicClaims
            {
                Ver = 1,
                Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
                DelegationMode = Validator.ModeRepresentative,
                Capabilities = new List<Claims.Capability> { CapDatabase(100) },
                ChainDepth = 0,
                MaxDepth = 1
            }
        };
        string tok = Jws.SignCompact(Serialize(h), Serialize(outer), "ES256", p.Issuer.Private);
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(tok, opts));
        Assert.Contains("requires a DA JWT", ex.Message);
    }

    [Fact]
    public void RepresentativeSubsetEnforced()
    {
        Pair p = Build();
        Validator.VerifyOptions opts = FullOpts(p, Iat + 60);

        Claims.Header h = new() { Alg = "ES256", Typ = Validator.TypOuter, Kid = "ca-2026-01" };
        Claims.OuterClaims outer = new()
        {
            Iss = Issuer,
            Sub = AgentId,
            Aud = new Claims.Audience(new List<string> { Audience }),
            Iat = Iat,
            Exp = Iat + 3600,
            Jti = p.Nonce,
            Cnf = new Claims.Cnf { Jkt = p.Jkt },
            Aic = new Claims.AicClaims
            {
                Ver = 1,
                Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
                DelegationMode = Validator.ModeRepresentative,
                Capabilities = new List<Claims.Capability> { new() { Scheme = "database", Id = "query:DELETE" } },
                ChainDepth = 0,
                MaxDepth = 1
            }
        };
        Claims.Header daHdr = new() { Alg = "ES256", Typ = Validator.TypDa, Kid = "principal-1" };
        Claims.DaClaims da = new()
        {
            Ver = 1,
            AgentId = AgentId,
            Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
            Reason = new Claims.Reason { Code = "DATA_ANALYSIS", Desc = "window" },
            Capabilities = new List<Claims.Capability> { new() { Scheme = "database", Id = "query:DELETE" } },
            DelegationMode = Validator.ModeRepresentative,
            RequestedLifetime = 3600,
            Ts = Iat,
            Nonce = p.Nonce
        };
        outer.Da = Jws.SignCompact(Serialize(daHdr), Serialize(da), "ES256", p.Principal.Private);
        string tok = Jws.SignCompact(Serialize(h), Serialize(outer), "ES256", p.Issuer.Private);

        opts.Pa = new Claims.PaClaims
        {
            Ver = 1,
            Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
            Grants = new List<Claims.Capability>
            {
                new() { Scheme = "database", Id = "query:SELECT", Params = JwtJson.Parse("{\"max_rows\":100}") }
            },
            DelegationPolicy = new Claims.DelegationPolicy { AllowedMode = Validator.AllowedModeRepresentative }
        };
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(tok, opts));
        Assert.Contains("step6", ex.Message);
    }

    [Fact]
    public void GoGeneratedOuterTokenParsesAndVerifies()
    {
        byte[] principalSpki = KeyHash.ParseJwk(System.Text.Encoding.UTF8.GetBytes(GoFixtures.PrincipalJwkJson));

        Jws.VerifyCompact(GoFixtures.DaToken, "ES256", SigAlgorithms.PublicKeyFromSpki(principalSpki)!);
        Jws.VerifyCompact(TokenFixtures.JwtValidatorOuterToken, "ES256", SigAlgorithms.PublicKeyFromSpki(principalSpki)!);

        Claims.OuterClaims parsed = JsonSerializer.Deserialize<Claims.OuterClaims>(
            Jws.ParseCompact(TokenFixtures.JwtValidatorOuterToken)[1], JwtJson.WireOptions)!;
        Assert.Equal("agent:db-analyst-01", parsed.Sub);
        Assert.Equal(Issuer, parsed.Iss);
        Assert.Equal(Validator.ModeRepresentative, parsed.Aic!.DelegationMode);
        Assert.Equal("0ZcOCORZNYy-DWpqq30jZyHnXgk7dNsQo0c1V3iR4vY", parsed.Cnf!.Jkt);
        Claims.DaClaims daParsed = JsonSerializer.Deserialize<Claims.DaClaims>(
            Jws.ParseCompact(GoFixtures.DaToken)[1], JwtJson.WireOptions)!;
        Assert.Equal("agent:db-analyst-01", daParsed.AgentId);

        Validator.VerifyOptions opts = new()
        {
            Now = FromEpoch(Iat + 60),
            IssuerSpki = new Dictionary<string, byte[]> { ["ca-2026-01"] = principalSpki },
            PrincipalJwks = new Dictionary<string, byte[]> { ["principal-zhangsan-2026"] = principalSpki },
            RequestContext = Ctx(Iat + 60, "10.1.2.3", 1)
        };
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(TokenFixtures.JwtValidatorOuterToken, opts));
        Assert.True(ex.Message.Contains("key_hash mismatch") || ex.Message.Contains("nonce") || ex.Message.Contains("step4"), ex.Message);
    }

    internal static class GoFixtures
    {
        public const string DaToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImFpYytkYStqd3QiLCJraWQiOiJwcmluY2lwYWwtemhhbmdzYW4tMjAyNiJ9.eyJ2ZXIiOjEsImFnZW50X2lkIjoiYWdlbnQ6ZGItYW5hbHlzdC0wMSIsInByaW5jaXBhbCI6eyJyZWFsbSI6ImNvcnAuY29tIiwiaWQiOiJ6aGFuZ3NhbiIsImtleV9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImhhc2hfYWxnIjoic2hhLTI1NiJ9LCJyZWFzb24iOnsiY29kZSI6IkRBVEFfQU5BTFlTSVMiLCJkZXNjIjoiU2NoZWR1bGVkIHByb2R1Y3Rpb24gZGF0YSBhbmFseXNpcyB3aW5kb3cifSwiY2FwYWJpbGl0aWVzIjpbeyJzY2hlbWUiOiJkYXRhYmFzZSIsImlkIjoicXVlcnk6U0VMRUNUIiwicGFyYW1zIjp7Im1heF9yb3dzIjoxMDB9fV0sImRlbGVnYXRpb25fbW9kZSI6InJlcHJlc2VudGF0aXZlIiwiY29uc3RyYWludHMiOlt7InNjaGVtZSI6InZhcndvZi9jb25zdHJhaW50LXYxIiwiaWQiOiJhbGxvd2VkLWNpZHIiLCJwYXJhbXMiOlsiMTAuMC4wLjAvOCJdfV0sInJlcXVlc3RlZF9saWZldGltZSI6MzYwMCwidHMiOjE3NTU0OTk5MDAsIm5vbmNlIjoiYUJjRGVGZ0hpSmtMbU5vUHFSc1R1VndYeVowMTIzNDU2Nzg5YWJjZGVmIn0.RUqMf76xEbbenvXz-3UsxEmV2M5_WwsGfr-i9eeI0zeesoaiUi_zvgrLUs9MiSgffPd4WV3nlIZ7U1daEJtsTw";

        public const string PrincipalJwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"rN1es49KexLagupeD_zOIiz974abUS-HWkDLW6sxUu4\",\"y\":\"B0uChX3GHDsRiVTSaXujwS_Nu_SJ9HtaXRpUMF8EVX4\"}";
    }
}
