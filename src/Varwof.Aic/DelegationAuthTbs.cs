using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// To-be-signed data for the DelegationAuthorization signature (Go
/// types.DelegationAuthTBS).
/// Field order: version, agentId, principalUid, reason, capabilities,
/// delegationMode, authorizationConstraints, requestedLifetime, timestamp,
/// nonce.
/// </summary>
public sealed class DelegationAuthTbs : IEquatable<DelegationAuthTbs>
{
    public int Version { get; }
    public string AgentId { get; }
    public PrincipalUid PrincipalUid { get; }
    public Reason Reason { get; }
    public IReadOnlyList<Capability> Capabilities { get; }
    public DelegationMode DelegationMode { get; }
    public IReadOnlyList<Capability> AuthorizationConstraints { get; }
    public int RequestedLifetime { get; }
    public DateTime Timestamp { get; }
    public byte[]? Nonce { get; }

    public DelegationAuthTbs(
        int version,
        string agentId,
        PrincipalUid principalUid,
        Reason reason,
        IReadOnlyList<Capability>? capabilities,
        DelegationMode delegationMode,
        IReadOnlyList<Capability>? authorizationConstraints,
        int requestedLifetime,
        DateTime timestamp,
        byte[]? nonce)
    {
        Version = version;
        AgentId = agentId ?? throw new ArgumentNullException(nameof(agentId));
        PrincipalUid = principalUid ?? throw new ArgumentNullException(nameof(principalUid));
        Reason = reason ?? throw new ArgumentNullException(nameof(reason));
        Capabilities = capabilities ?? (IReadOnlyList<Capability>)Array.Empty<Capability>();
        DelegationMode = delegationMode;
        AuthorizationConstraints = authorizationConstraints ?? (IReadOnlyList<Capability>)Array.Empty<Capability>();
        RequestedLifetime = requestedLifetime;
        Timestamp = timestamp;
        Nonce = nonce is null ? null : (byte[])nonce.Clone();
    }

    /// <summary>Build the TBS from the corresponding (unsigned) AIC.</summary>
    public static DelegationAuthTbs FromAic(Aic aic) => new(
        aic.Version,
        aic.AgentId,
        aic.PrincipalUid,
        aic.DelegationAuthorization is null ? Reason.Empty : aic.DelegationAuthorization.Reason,
        aic.Capabilities,
        aic.DelegationMode,
        aic.AuthorizationConstraints,
        aic.DelegationAuthorization is null ? 0 : aic.DelegationAuthorization.RequestedLifetime,
        aic.DelegationAuthorization is null ? DateTime.UnixEpoch : aic.DelegationAuthorization.Timestamp,
        aic.DelegationAuthorization?.Nonce);

    public byte[] Encode()
    {
        var elems = new List<Asn1Encodable>
        {
            Der.Integer(Version),
            Der.Utf8(AgentId),
            Asn1Object.FromByteArray(PrincipalUid.Encode()),
            Asn1Object.FromByteArray(Reason.Encode()),
            EncodeCapabilities(Capabilities),
            Der.Integer((int)DelegationMode)
        };
        if (AuthorizationConstraints.Count > 0)
        {
            elems.Add(Der.Explicit(0, EncodeCapabilities(AuthorizationConstraints)));
        }
        elems.Add(Der.Integer(RequestedLifetime));
        elems.Add(Der.Generalized(Timestamp));
        elems.Add(new DerOctetString(Nonce ?? Array.Empty<byte>()));
        return Der.DerEncode(Der.DerSequence(elems.ToArray()));
    }

    private static Asn1Object EncodeCapabilities(IReadOnlyList<Capability> caps)
    {
        var arr = new Asn1Encodable[caps.Count];
        for (int i = 0; i < caps.Count; i++)
        {
            arr[i] = Asn1Object.FromByteArray(caps[i].Encode());
        }
        return new DerSequence(arr).ToAsn1Object();
    }

    public static DelegationAuthTbs Decode(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        int ix = 0;
        int version = Der.IntValue(seq[ix++]);
        string agentId = Der.StringValue(seq[ix++]);
        PrincipalUid uid = PrincipalUid.Decode(seq[ix++]);
        Reason reason = Reason.Decode(seq[ix++]);
        List<Capability> caps = DecodeCapabilities(seq[ix++]);
        // Remaining elements are strictly ordered per Encode()/Go: delegationMode,
        // optional [0] constraints, requestedLifetime, timestamp, nonce.
        if (ix >= seq.Count || !(seq[ix].ToAsn1Object() is DerInteger modeInt))
        {
            throw new AicException("DelegationAuthTbs: delegationMode missing");
        }
        DelegationMode mode = DelegationModes.FromValue((int)modeInt.Value.LongValue);
        ix++;
        List<Capability> constraints = new();
        if (ix < seq.Count)
        {
            Asn1Object? tagInner = Der.OptionalTagContent(seq[ix], 0);
            if (tagInner is not null)
            {
                constraints = DecodeCapabilities(tagInner);
                ix++;
            }
        }
        if (ix >= seq.Count || !(seq[ix].ToAsn1Object() is DerInteger life))
        {
            throw new AicException("DelegationAuthTbs: requestedLifetime missing");
        }
        int lifetime = (int)life.Value.LongValue;
        ix++;
        if (ix >= seq.Count || !(seq[ix].ToAsn1Object() is Asn1GeneralizedTime g))
        {
            throw new AicException("DelegationAuthTbs: timestamp missing");
        }
        DateTime ts = Der.ToInstant(g);
        ix++;
        if (ix >= seq.Count || !(seq[ix].ToAsn1Object() is Asn1OctetString oct))
        {
            throw new AicException("DelegationAuthTbs: nonce missing");
        }
        byte[] nonce = oct.GetOctets();
        ix++;
        if (ix != seq.Count)
        {
            throw new AicException("DelegationAuthTbs: unexpected trailing elements");
        }
        return new DelegationAuthTbs(version, agentId, uid, reason, caps, mode, constraints, lifetime, ts, nonce);
    }

    public static DelegationAuthTbs Parse(byte[] derBytes) => Decode(Der.FromBytes(derBytes));

    private static List<Capability> DecodeCapabilities(Asn1Encodable e)
    {
        Asn1Sequence seq = Der.Seq(e);
        var result = new List<Capability>(seq.Count);
        for (int i = 0; i < seq.Count; i++)
        {
            result.Add(Capability.Decode(seq[i]));
        }
        return result;
    }

    public bool Equals(DelegationAuthTbs? other) => other is not null
        && Version == other.Version
        && RequestedLifetime == other.RequestedLifetime
        && AgentId == other.AgentId
        && PrincipalUid.Equals(other.PrincipalUid)
        && Reason.Equals(other.Reason)
        && Capabilities.SequenceEqual(other.Capabilities)
        && DelegationMode == other.DelegationMode
        && AuthorizationConstraints.SequenceEqual(other.AuthorizationConstraints)
        && Timestamp == other.Timestamp
        && (Nonce ?? Array.Empty<byte>()).SequenceEqual(other.Nonce ?? Array.Empty<byte>());

    public override bool Equals(object? obj) => Equals(obj as DelegationAuthTbs);

    public override int GetHashCode() => HashCode.Combine(
        Version, AgentId, PrincipalUid, Reason, RequestedLifetime, Timestamp, Nonce?.Length ?? 0);
}