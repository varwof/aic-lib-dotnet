using System;
using System.Collections.Generic;
using Xunit;

namespace Varwof.Aic.Tests;

/// <summary>
/// Byte-for-byte DER compatibility with the Go reference implementation
/// (encoding/asn1.Marshal). Vectors captured in DerVectors.cs.
/// </summary>
public class DerVectorsTest
{
    private static byte[] KeyHash() => KeyHash(0x00);

    private static byte[] KeyHash(int start)
    {
        byte[] k = new byte[32];
        for (int i = 0; i < k.Length; i++)
        {
            k[i] = (byte)(start + i);
        }
        return k;
    }

    private static byte[] Nonce()
    {
        byte[] n = new byte[32];
        for (int i = 0; i < n.Length; i++)
        {
            n[i] = (byte)(0xa0 + i);
        }
        return n;
    }

    private static byte[] SigValue()
    {
        byte[] s = new byte[70];
        for (int i = 0; i < s.Length; i++)
        {
            s[i] = (byte)(0x20 + i);
        }
        return s;
    }

    private static readonly DateTime Ts = new(2026, 8, 18, 0, 0, 0, DateTimeKind.Utc);

    private static Aic SimpleAic()
    {
        PrincipalUid pu = new(1, "corp.com", "zhangsan", KeyHash(), null);
        Capability cap = new("http", "GET:/api/v1/users", new byte[] { 0x01, 0x02 });
        return new Aic(1, "agent-109", pu, new List<Capability> { cap }, DelegationMode.Authorized, new List<Capability>(), null, new List<ExtField>());
    }

    private static Aic FullAic()
    {
        PrincipalUid pu = new(1, "corp.com", "zhangsan", KeyHash(), new AlgorithmIdentifier(Oids.Sha256));
        Capability http = new("http", "GET:/api/v1/users", new byte[] { 0x01, 0x02 });
        Capability db = new("db", "SELECT:*");
        Capability cidr = new("varwof/constraint-v1", "allowed-cidr",
            System.Text.Encoding.UTF8.GetBytes("[\"10.0.0.0/8\"]"));
        DelegationAuthorization da = new(new Reason("http", "Need to query users"), 3600, Ts, Nonce(),
            new AlgorithmIdentifier(Oids.EcdsaWithSha256), SigValue());
        return new Aic(1, "agent-109", pu, new List<Capability> { http, db }, DelegationMode.Authorized,
            new List<Capability> { cidr }, da, new List<ExtField>());
    }

    [Fact]
    public void AicSimpleMatchesGo() => Assert.Equal(DerVectors.AicSimple, TestHex.EncodeHex(SimpleAic().Encode()));

    [Fact]
    public void AicFullMatchesGo() => Assert.Equal(DerVectors.AicFull, TestHex.EncodeHex(FullAic().Encode()));

    [Fact]
    public void TbsMatchesGo()
    {
        Aic aic = FullAic();
        Assert.Equal(DerVectors.Tbs, TestHex.EncodeHex(DelegationAuthTbs.FromAic(aic).Encode()));
    }

    [Fact]
    public void PaMatchesGo()
    {
        Capability cidr = new("varwof/constraint-v1", "allowed-cidr",
            System.Text.Encoding.UTF8.GetBytes("[\"10.0.0.0/8\"]"));
        PrincipalAuthorization pa = new(1,
            new List<Capability> { new("database", "query:SELECT"), new("http", "GET:*") },
            new List<Capability> { cidr },
            new DelegationPolicy(1, 8, 1, null), new List<ExtField>());
        Assert.Equal(DerVectors.Pa, TestHex.EncodeHex(pa.Encode()));
    }

    [Fact]
    public void CapabilityMatchesGo()
        => Assert.Equal(DerVectors.Cap, TestHex.EncodeHex(new Capability("http", "GET:/api/v1/users", new byte[] { 0x01, 0x02 }).Encode()));

    [Fact]
    public void PrincipalUidMatchesGo()
    {
        PrincipalUid full = new(1, "corp.com", "zhangsan", KeyHash(), new AlgorithmIdentifier(Oids.Sha256));
        Assert.Equal(DerVectors.PuFull, TestHex.EncodeHex(full.Encode()));
        PrincipalUid simple = new(1, "corp.com", "zhangsan", KeyHash(), null);
        Assert.Equal(DerVectors.PuSimple, TestHex.EncodeHex(simple.Encode()));
    }

    [Fact]
    public void DelegationPolicyMatchesGo()
        => Assert.Equal(DerVectors.Dpol, TestHex.EncodeHex(new DelegationPolicy(1, 8, 1, null).Encode()));

    [Fact]
    public void DaRawMatchesGo()
    {
        DelegationAuthorization da = new(new Reason("http", "Need to query users"), 3600, Ts, Nonce(),
            new AlgorithmIdentifier(Oids.EcdsaWithSha256), SigValue());
        Assert.Equal(DerVectors.DaRaw, TestHex.EncodeHex(da.Encode()));
    }

    [Fact]
    public void ExtFieldMatchesGo()
    {
        ExtField ext = new(Oids.MarketAccessId, false, new byte[] { 0xde, 0xad });
        Assert.Equal(DerVectors.ExtField, TestHex.EncodeHex(ext.Encode()));
    }

    [Fact]
    public void DecodeThenReencodeIsByteStable()
    {
        Aic a = Aic.Parse(TestHex.DecodeHex(DerVectors.AicFull));
        Assert.Equal(DerVectors.AicFull, TestHex.EncodeHex(a.Encode()));
        Assert.True(a.DelegationAuthorization!.IsPresent());

        Aic s = Aic.Parse(TestHex.DecodeHex(DerVectors.AicSimple));
        Assert.Equal(DerVectors.AicSimple, TestHex.EncodeHex(s.Encode()));

        DelegationAuthTbs t = DelegationAuthTbs.Parse(TestHex.DecodeHex(DerVectors.Tbs));
        Assert.Equal(DerVectors.Tbs, TestHex.EncodeHex(t.Encode()));

        PrincipalAuthorization pa = PrincipalAuthorization.Parse(TestHex.DecodeHex(DerVectors.Pa));
        Assert.Equal(DerVectors.Pa, TestHex.EncodeHex(pa.Encode()));
    }
}
