using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Validation of Aic and its sub-structures. Port of Go ValidateAIC,
/// ValidatePrincipalUidKeyHash, and ValidateMaxConcurrentParam; rejects the
/// same inputs.
/// </summary>
public static class AicValidator
{
    private const string ConstraintScheme = "varwof/constraint-v1";
    private static readonly HashSet<string> ConstraintSchemes = new()
    {
        "constraint", "constraint-v1", ConstraintScheme
    };

    private static readonly List<DerObjectIdentifier> KnownExtensionOids = new()
    {
        Oids.AicAgentIdentity,
        Oids.AicDelegationAuthorization,
        Oids.PrincipalAuthorization,
        Oids.MarketAccessId
    };

    public static void Validate(Aic aic)
    {
        if (aic is null)
        {
            throw new AicException("aic: nil");
        }
        if (aic.AgentId.Length < 1 || aic.AgentId.Length > 256)
        {
            throw new AicException("aic: agentId length " + aic.AgentId.Length + ": must be 1-256");
        }
        if (aic.Version != 1 && aic.Version != 2)
        {
            throw new AicException("aic: version " + aic.Version + " must be 1 or 2");
        }
        System.Collections.Generic.IReadOnlyList<Capability> caps = aic.Capabilities;
        if (caps.Count > Limits.MaxCapabilities)
        {
            throw new AicException("aic: capabilities count " + caps.Count + " exceeds max " + Limits.MaxCapabilities);
        }
        for (int i = 0; i < caps.Count; i++)
        {
            Capability cap = caps[i];
            CheckLen("aic: capability[" + i + "].schemeId", cap.SchemeId, 1, 128);
            CheckLen("aic: capability[" + i + "].capabilityId", cap.CapabilityId, 1, 256);
            if (cap.HasParameters() && cap.Parameters!.Length > Limits.MaxCapParams)
            {
                throw new AicException("aic: capability[" + i + "].parameters length " + cap.Parameters!.Length
                    + ": must be 0-" + Limits.MaxCapParams);
            }
            if (ConstraintScheme == cap.SchemeId)
            {
                throw new AicException("aic: capability[" + i + "].schemeId \"" + ConstraintScheme
                    + "\": constraint scheme forbidden in capabilities");
            }
        }
        if (aic.Extensions.Count > Limits.MaxExtensionsSlots)
        {
            throw new AicException("aic: extensions count " + aic.Extensions.Count
                + " exceeds max " + Limits.MaxExtensionsSlots);
        }
        for (int i = 0; i < aic.Extensions.Count; i++)
        {
            ExtField ext = aic.Extensions[i];
            if (ext.Critical && !ContainsOid(KnownExtensionOids, ext.ExtnId))
            {
                throw new AicException("aic: extensions[" + i + "] has unknown critical OID " + ext.ExtnId.Id);
            }
        }
        PrincipalUid pu = aic.PrincipalUid;
        CheckLen("aic: principalUid.realm", pu.Realm, 1, 128);
        CheckLen("aic: principalUid.identifier", pu.Identifier, 1, 256);
        ValidatePrincipalUidKeyHash(pu);

        DelegationAuthorization? da = aic.DelegationAuthorization;
        if (da is null || !da.IsPresent())
        {
            throw new AicException("aic: delegationAuthorization is required but missing");
        }
        if (da.Reason.ReasonCode.Length == 0)
        {
            throw new AicException("aic: delegationAuth.reason.reasonCode: must not be empty");
        }
        if (da.Reason.Description.Length == 0)
        {
            throw new AicException("aic: delegationAuth.reason.description: must not be empty");
        }
        if (da.Reason.ReasonCode.Length > 64)
        {
            throw new AicException("aic: delegationAuth.reason.reasonCode length " + da.Reason.ReasonCode.Length + ": must be <= 64");
        }
        if (da.Reason.Description.Length > 512)
        {
            throw new AicException("aic: delegationAuth.reason.description length " + da.Reason.Description.Length + ": must be <= 512");
        }
        if (da.Nonce is null || da.Nonce.Length != Limits.MaxNonceLen)
        {
            throw new AicException("aic: delegationAuth.nonce length "
                + (da.Nonce is null ? 0 : da.Nonce.Length) + ": must be exactly " + Limits.MaxNonceLen + " bytes");
        }
        int lifetime = da.RequestedLifetime;
        if (lifetime == 0)
        {
            lifetime = Limits.MinRequestedLifetime;
        }
        if (lifetime < 1 || lifetime > Limits.MaxRequestedLifetime)
        {
            throw new AicException("aic: delegationAuth.requestedLifetime " + da.RequestedLifetime
                + ": must be 1-" + Limits.MaxRequestedLifetime);
        }
        ValidateConstraints("aic", aic.AuthorizationConstraints);
    }

    private static void ValidateConstraints(string prefix, IReadOnlyList<Capability> constraints)
    {
        if (constraints.Count > Limits.MaxAuthorizationConstraints)
        {
            throw new AicException(prefix + ": authorizationConstraints count " + constraints.Count
                + " exceeds max " + Limits.MaxAuthorizationConstraints);
        }
        for (int i = 0; i < constraints.Count; i++)
        {
            Capability c = constraints[i];
            if (!ConstraintSchemes.Contains(c.SchemeId))
            {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].schemeId \"" + c.SchemeId
                    + "\": must be \"constraint\", \"constraint-v1\", or \"varwof/constraint-v1\"");
            }
            if (c.CapabilityId.Length == 0)
            {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].capabilityId: must not be empty");
            }
            if (c.HasParameters() && c.Parameters!.Length > Limits.MaxConstraintParams)
            {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].parameters length "
                    + c.Parameters!.Length + ": must be 0-" + Limits.MaxConstraintParams);
            }
            if (c.HasParameters() && !JsonUtil.IsValidJson(c.Parameters!))
            {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].parameters: invalid JSON");
            }
            if (c.CapabilityId == "max-concurrent" && c.HasParameters())
            {
                try
                {
                    ValidateMaxConcurrentParam(c.Parameters!);
                }
                catch (AicException ex)
                {
                    throw new AicException(prefix + ": authorizationConstraints[" + i + "]: " + ex.Message);
                }
            }
        }
    }

    /// <summary>keyHash length must equal the declared hashAlgo output length (default SHA-256 = 32).</summary>
    public static void ValidatePrincipalUidKeyHash(PrincipalUid pu)
    {
        if (pu is null || pu.KeyHash.Length == 0)
        {
            throw new AicException("aic: principalUid.keyHash: required");
        }
        DerObjectIdentifier algo = pu.HashAlgoOid();
        string name = HashAlgorithms.NameForOid(algo);
        if (name.Length == 0)
        {
            throw new AicException("aic: principalUid.hashAlgo " + algo.Id + ": unsupported keyHash algorithm");
        }
        int? want = HashAlgorithms.OutputLength(algo);
        if (want is null)
        {
            throw new AicException("aic: principalUid.hashAlgo " + algo.Id + ": no output length mapping (requires external dependency)");
        }
        if (pu.KeyHash.Length != want.Value)
        {
            throw new AicException("aic: principalUid.keyHash length " + pu.KeyHash.Length
                + ": must be " + want + " (" + name + ")");
        }
    }

    /// <summary>{"max": N} with N in 1..1024; empty input is "not configured" (valid).</summary>
    public static void ValidateMaxConcurrentParam(byte[] raw)
    {
        int start = 0;
        int end = raw.Length;
        while (start < end && IsSpace(raw[start]))
        {
            start++;
        }
        while (end > start && IsSpace(raw[end - 1]))
        {
            end--;
        }
        if (end - start == 0)
        {
            return;
        }
        try
        {
            JsonNode? node = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(raw, start, end - start));
            if (node is not JsonObject obj || obj.Count != 1 || obj["max"] is null || obj["max"]!.GetValueKind() != System.Text.Json.JsonValueKind.Number)
            {
                throw new AicException("max-concurrent: must be JSON object {\"max\": N}");
            }
            long max = obj["max"]!.GetValue<long>();
            if (max < 1 || max > 1024)
            {
                throw new AicException("max-concurrent: max " + max + ": must be 1-1024");
            }
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("max-concurrent: invalid JSON: " + ex.Message);
        }
    }

    private static bool IsSpace(byte b) => b is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r';

    private static bool ContainsOid(List<DerObjectIdentifier> list, DerObjectIdentifier oid)
    {
        foreach (DerObjectIdentifier x in list)
        {
            if (x.Equals(oid))
            {
                return true;
            }
        }
        return false;
    }

    private static void CheckLen(string what, string? s, int min, int max)
    {
        if (s is null || s.Length < min || s.Length > max)
        {
            throw new AicException(what + " length " + (s?.Length ?? 0) + ": must be " + min + "-" + max);
        }
    }
}