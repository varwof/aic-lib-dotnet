using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Varwof.Aic.Jwt;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>
/// Cross-language conformance: tokens with ver=2 DA (-01 claims) in both
/// authorized and representative modes validate end-to-end, including
/// key-binding, mode-dependent sub/act rules, and DER encoding.
/// </summary>
public class GoConformanceTest
{
    private const long Iat = 1755500000L;
    private const string AgentId = "agent:db-analyst-01";
    private const string Realm = "corp.com";
    private const string PrincipalId = "zhangsan";
    private const string Issuer = "https://ca.example.com/aic";
    private const string Audience = "https://gw.example.com";

    private static DateTime FromEpoch(long sec)
        => DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime;

    private static byte[] PubKey(string spkiB64) => Convert.FromBase64String(spkiB64);

    private static AsymmetricCipherKeyPair Ec()
    {
        X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), curve.Curve.FieldSize));
        return keyGen.GenerateKeyPair();
    }

    private static Constraints.RequestContext Ctx(long now, string ip)
        => new()
        {
            Now = FromEpoch(now),
            SourceIp = IPAddress.Parse(ip),
            ConcurrentCount = 1
        };

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

    private static Pair BuildPair()
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
        return p;
    }

    private static string SignDa(Pair p, Claims.DaClaims da)
    {
        Claims.Header hdr = new() { Alg = "ES256", Typ = Validator.TypDa, Kid = "principal-1" };
        return Jws.SignCompact(
            JsonSerializer.SerializeToUtf8Bytes(hdr, JwtJson.WireOptions),
            JsonSerializer.SerializeToUtf8Bytes(da, JwtJson.WireOptions),
            "ES256", p.Principal.Private);
    }

    private static string SignOuter(Pair p, Claims.OuterClaims outer)
    {
        Claims.Header hdr = new() { Alg = "ES256", Typ = Validator.TypOuter, Kid = "ca-2026-01" };
        return Jws.SignCompact(
            JsonSerializer.SerializeToUtf8Bytes(hdr, JwtJson.WireOptions),
            JsonSerializer.SerializeToUtf8Bytes(outer, JwtJson.WireOptions),
            "ES256", p.Issuer.Private);
    }

    private static Validator.VerifyOptions BaseOpts(Pair p, long now)
    {
        return new Validator.VerifyOptions
        {
            Now = FromEpoch(now),
            ExpectedIssuer = Issuer,
            ExpectedAudience = new List<string> { Audience },
            IssuerSpki = new Dictionary<string, byte[]> { ["ca-2026-01"] = p.IssuerSpki },
            PrincipalJwks = new Dictionary<string, byte[]> { ["principal-1"] = p.PrincipalSpki },
            PresenterSpki = p.PrincipalSpki,
            NonceStore = NonceStore.NewMemNonceStore(),
            RequestContext = Ctx(now, "10.1.2.3"),
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
    }

    private static Pair BuildAuthorizedPair(out string daToken, out string outerToken)
    {
        Pair p = BuildPair();
        Claims.DaClaims da = new()
        {
            Ver = 2,
            Iss = Realm + ":" + PrincipalId,
            Sub = AgentId,
            Aud = new Claims.Audience(new List<string> { Issuer }),
            Exp = Iat + 3600,
            Iat = Iat,
            Jti = p.Nonce,
            AgentId = AgentId,
            Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
            Reason = new Claims.Reason { Code = "DATA_ANALYSIS", Desc = "Scheduled production data analysis window" },
            Capabilities = new List<Claims.Capability> { new() { Scheme = "database", Id = "query:SELECT", Params = JwtJson.Parse("{\"max_rows\":100}") } },
            DelegationMode = Validator.ModeAuthorized,
            Constraints = new List<Claims.Capability>
            {
                new() { Scheme = "varwof/constraint-v1", Id = "allowed-cidr", Params = JwtJson.Parse("[\"10.0.0.0/8\"]") }
            },
            RequestedLifetime = 3600,
            Ts = Iat,
            Nonce = p.Nonce
        };
        daToken = SignDa(p, da);
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
                Capabilities = new List<Claims.Capability> { new() { Scheme = "database", Id = "query:SELECT", Params = JwtJson.Parse("{\"max_rows\":100}") } },
                ChainDepth = 0,
                MaxDepth = 1,
                Constraints = new List<Claims.Capability>
                {
                    new() { Scheme = "varwof/constraint-v1", Id = "allowed-cidr", Params = JwtJson.Parse("[\"10.0.0.0/8\"]") }
                }
            },
            Da = daToken
        };
        outerToken = SignOuter(p, outer);
        return p;
    }

    private static Pair BuildRepresentativePair(out string daToken, out string outerToken)
    {
        Pair p = BuildPair();
        Claims.DaClaims da = new()
        {
            Ver = 2,
            Iss = Realm + ":" + PrincipalId,
            Sub = Realm + ":" + PrincipalId,
            Aud = new Claims.Audience(new List<string> { Issuer }),
            Exp = Iat + 3600,
            Iat = Iat,
            Jti = p.Nonce,
            AgentId = AgentId,
            Principal = new Claims.Principal { Realm = Realm, Id = PrincipalId, KeyHash = p.KeyHash, HashAlg = "sha-256" },
            Reason = new Claims.Reason { Code = "DATA_ANALYSIS", Desc = "Scheduled production data analysis window" },
            Capabilities = new List<Claims.Capability> { new() { Scheme = "database", Id = "query:SELECT", Params = JwtJson.Parse("{\"max_rows\":100}") } },
            DelegationMode = Validator.ModeRepresentative,
            Constraints = new List<Claims.Capability>
            {
                new() { Scheme = "varwof/constraint-v1", Id = "allowed-cidr", Params = JwtJson.Parse("[\"10.0.0.0/8\"]") }
            },
            RequestedLifetime = 3600,
            Ts = Iat,
            Nonce = p.Nonce
        };
        daToken = SignDa(p, da);
        Claims.OuterClaims outer = new()
        {
            Iss = Issuer,
            Sub = Realm + ":" + PrincipalId,
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
                Capabilities = new List<Claims.Capability> { new() { Scheme = "database", Id = "query:SELECT", Params = JwtJson.Parse("{\"max_rows\":100}") } },
                ChainDepth = 0,
                MaxDepth = 1,
                Constraints = new List<Claims.Capability>
                {
                    new() { Scheme = "varwof/constraint-v1", Id = "allowed-cidr", Params = JwtJson.Parse("[\"10.0.0.0/8\"]") }
                }
            },
            Da = daToken,
            Act = new Claims.Actor { Sub = AgentId }
        };
        outerToken = SignOuter(p, outer);
        return p;
    }

    private static Validator.VerifyOptions OptsForRepresentative(Pair p, long now)
    {
        Validator.VerifyOptions opts = BaseOpts(p, now);
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
        return opts;
    }

    [Fact]
    public void AuthorizedModePermits()
    {
        Pair p = BuildAuthorizedPair(out _, out string outerToken);
        Validator.VerifyOptions opts = BaseOpts(p, Iat + 60);
        Validator.Decision d = Validator.Validate(outerToken, opts);
        Assert.True(d.Permit);
        Assert.Equal(AgentId, d.Actor);
        Assert.Equal(PrincipalId, d.Principal);
        Assert.Single(d.Capabilities!);
    }

    [Fact]
    public void RepresentativeModePermits()
    {
        Pair p = BuildRepresentativePair(out _, out string outerToken);
        Validator.VerifyOptions opts = OptsForRepresentative(p, Iat + 60);
        Validator.Decision d = Validator.Validate(outerToken, opts);
        Assert.True(d.Permit);
        Assert.Equal(PrincipalId, d.Actor);
        Assert.Equal(AgentId, d.Executor);
        Assert.Equal(PrincipalId, d.Principal);
        Assert.Single(d.Capabilities!);
    }

    [Fact]
    public void AuthorizedModeConstraintViolationRejected()
    {
        Pair p = BuildAuthorizedPair(out _, out string outerToken);
        Validator.VerifyOptions opts = BaseOpts(p, Iat + 60);
        opts.RequestContext = Ctx(Iat + 60, "192.168.9.9");
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(outerToken, opts));
        Assert.Contains("step7", ex.Message);
    }

    [Fact]
    public void AuthorizedModeExpiredRejected()
    {
        Pair p = BuildAuthorizedPair(out _, out string outerToken);
        Validator.VerifyOptions opts = BaseOpts(p, Iat + 4000);
        opts.RequestContext = Ctx(Iat + 4000, "10.1.2.3");
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(outerToken, opts));
        Assert.Contains("step3", ex.Message);
    }

    [Fact]
    public void RepresentativeModeConstraintViolationRejected()
    {
        Pair p = BuildRepresentativePair(out _, out string outerToken);
        Validator.VerifyOptions opts = OptsForRepresentative(p, Iat + 60);
        opts.RequestContext = Ctx(Iat + 60, "192.168.9.9");
        AicException ex = Assert.Throws<AicException>(() => Validator.Validate(outerToken, opts));
        Assert.Contains("step7", ex.Message);
    }
}
