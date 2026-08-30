using System;
using System.Collections.Generic;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>Port of Go ValidateAIC / ValidatePrincipalAuthorization behaviour;
/// accept the canonical AIC, reject each spec violation.</summary>
public class AicValidatorTest
{
    private static byte[] KeyHash()
    {
        byte[] k = new byte[32];
        for (int i = 0; i < k.Length; i++)
        {
            k[i] = (byte)i;
        }
        return k;
    }

    private static byte[] Nonce()
    {
        byte[] n = new byte[32];
        for (int i = 0; i < n.Length; i++)
        {
            n[i] = (byte)i;
        }
        return n;
    }

    private static readonly DateTime Ts = new(2026, 8, 18, 0, 0, 0, DateTimeKind.Utc);

    private static Aic ValidAic()
    {
        PrincipalUid pu = new(1, "corp.com", "zhangsan", KeyHash(), null);
        DelegationAuthorization da = new(new Reason("http", "Need to query users"), 3600, Ts, Nonce(),
            new AlgorithmIdentifier(Oids.EcdsaWithSha256), new byte[70]);
        return new Aic(1, "agent-109", pu,
            new List<Capability> { new("http", "GET:/api/v1/users") },
            DelegationMode.Authorized, new List<Capability>(), da, new List<ExtField>());
    }

    [Fact]
    public void ValidAicPasses() => AicValidator.Validate(ValidAic());

    [Fact]
    public void AgentIdEmptyRejected()
    {
        Aic a = ValidAic();
        Aic bad = new(a.Version, "", a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, a.DelegationAuthorization, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void MissingDaRejected()
    {
        Aic a = ValidAic();
        Aic noDa = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, null, a.Extensions);
        AicException ex = Assert.Throws<AicException>(() => AicValidator.Validate(noDa));
        Assert.Contains("delegationAuthorization is required", ex.Message);
    }

    [Fact]
    public void ReasonMustBeNonEmpty()
    {
        Aic a = ValidAic();
        DelegationAuthorization da = a.DelegationAuthorization!;
        DelegationAuthorization badReason = new(new Reason("", da.Reason.Description), da.RequestedLifetime,
            da.Timestamp, da.Nonce, da.SignatureAlgorithm, da.SignatureValue);
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, badReason, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void NonceLengthMustBe32()
    {
        Aic a = ValidAic();
        DelegationAuthorization da = a.DelegationAuthorization!;
        DelegationAuthorization badNonce = new(da.Reason, da.RequestedLifetime, da.Timestamp, new byte[16],
            da.SignatureAlgorithm, da.SignatureValue);
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, badNonce, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void RequestedLifetimeBounds()
    {
        Aic a = ValidAic();
        DelegationAuthorization da = a.DelegationAuthorization!;

        DelegationAuthorization tooLong = new(da.Reason, 86401, da.Timestamp, da.Nonce, da.SignatureAlgorithm, da.SignatureValue);
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, tooLong, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));

        DelegationAuthorization zero = new(da.Reason, 0, da.Timestamp, da.Nonce, da.SignatureAlgorithm, da.SignatureValue);
        Aic ok = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, zero, a.Extensions);
        AicValidator.Validate(ok);

        DelegationAuthorization negative = new(da.Reason, -1, da.Timestamp, da.Nonce, da.SignatureAlgorithm, da.SignatureValue);
        Aic neg = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, negative, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(neg));
    }

    [Fact]
    public void ConstraintSchemeWhitelist()
    {
        Aic a = ValidAic();
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            new List<Capability> { new("evil-scheme", "x", new byte[] { 0x01 }) },
            a.DelegationAuthorization, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void ConstraintParamsMustBeValidJson()
    {
        Aic a = ValidAic();
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            new List<Capability> { new("varwof/constraint-v1", "x", new byte[] { 0x01, 0xc3 }) },
            a.DelegationAuthorization, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void CapabilitiesMustNotUseConstraintScheme()
    {
        Aic a = ValidAic();
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid,
            new List<Capability> { new("varwof/constraint-v1", "allowed-cidr", System.Text.Encoding.UTF8.GetBytes("[]")) },
            a.DelegationMode, a.AuthorizationConstraints, a.DelegationAuthorization, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void KeyHashMustMatchHashAlgoLength()
    {
        Aic a = ValidAic();
        PrincipalUid pu = new(1, "corp.com", "zhangsan", new byte[16], null);
        Aic bad = new(a.Version, a.AgentId, pu, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, a.DelegationAuthorization, a.Extensions);
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void UnknownCriticalExtensionRejected()
    {
        Aic a = ValidAic();
        ExtField unknown = new(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.2.3.4.5"), true, new byte[] { 0x01 });
        Aic bad = new(a.Version, a.AgentId, a.PrincipalUid, a.Capabilities, a.DelegationMode,
            a.AuthorizationConstraints, a.DelegationAuthorization, new List<ExtField> { unknown });
        Assert.Throws<AicException>(() => AicValidator.Validate(bad));
    }

    [Fact]
    public void MaxConcurrentValidation()
    {
        AicValidator.ValidateMaxConcurrentParam(System.Text.Encoding.UTF8.GetBytes("{\"max\": 16}"));
        Assert.Throws<AicException>(() => AicValidator.ValidateMaxConcurrentParam(System.Text.Encoding.UTF8.GetBytes("{\"max\": 0}")));
        Assert.Throws<AicException>(() => AicValidator.ValidateMaxConcurrentParam(System.Text.Encoding.UTF8.GetBytes("{\"max\": 1025}")));
        Assert.Throws<AicException>(() => AicValidator.ValidateMaxConcurrentParam(System.Text.Encoding.UTF8.GetBytes("not-json")));
        AicValidator.ValidateMaxConcurrentParam(Array.Empty<byte>());
    }

    [Fact]
    public void PrincipalAuthorizationValidation()
    {
        PrincipalAuthorizationValidator.Validate(new PrincipalAuthorization(1,
            new List<Capability> { new("database", "query:SELECT") },
            new List<Capability> { new("varwof/constraint-v1", "allowed-cidr", System.Text.Encoding.UTF8.GetBytes("[]")) },
            new DelegationPolicy(1, 8, 1, null), new List<ExtField>()));
        Assert.Throws<AicException>(() => PrincipalAuthorizationValidator.Validate(new PrincipalAuthorization(1,
            new List<Capability> { new("bad", "grant") },
            new List<Capability> { new("not-constraint", "x") }, null, new List<ExtField>())));
        Assert.Throws<AicException>(() => PrincipalAuthorizationValidator.Validate(new PrincipalAuthorization(1,
            new List<Capability>(), new List<Capability>(), new DelegationPolicy(1, 8, 2, null), new List<ExtField>())));
    }

    [Fact]
    public void PrincipalUidDisplayFormat()
    {
        PrincipalUid pu = new(1, "corp.com", "zhangsan", KeyHash(), null);
        string s = pu.DisplayString();
        Assert.Equal(
            new PrincipalUid(1, "corp.com", "zhangsan", KeyHash(), new AlgorithmIdentifier(Oids.Sha256)),
            PrincipalUid.ParseDisplayString(s));
        Assert.Throws<AicException>(() => PrincipalUid.ParseDisplayString("corp.com:zhangsan"));
        Assert.Throws<AicException>(() => PrincipalUid.ParseDisplayString("a:b:c:d"));
    }
}
