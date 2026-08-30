using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;

namespace Varwof.Aic;

/// <summary>
/// Validation of PrincipalAuthorization. Port of Go
/// ValidatePrincipalAuthorization / AicValidator.PrincipalAuthorization.
/// </summary>
public static class PrincipalAuthorizationValidator
{
    private const string ConstraintScheme = "varwof/constraint-v1";
    private static readonly HashSet<string> ConstraintSchemesValidation = new()
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

    public static void Validate(PrincipalAuthorization pa)
    {
        if (pa is null)
        {
            throw new AicException("principalAuthorization: nil");
        }

        System.Collections.Generic.IReadOnlyList<Capability> caps = pa.Capabilities;
        if (caps.Count > Limits.MaxCapabilities)
        {
            throw new AicException("principalAuthorization: capabilities count " + caps.Count
                + " exceeds max " + Limits.MaxCapabilities);
        }
        for (int i = 0; i < caps.Count; i++)
        {
            Capability c = caps[i];
            CheckLen("principalAuthorization: capability[" + i + "].schemeId", c.SchemeId, 1, 128);
            CheckLen("principalAuthorization: capability[" + i + "].capabilityId", c.CapabilityId, 1, 256);
            if (c.HasParameters() && c.Parameters!.Length > Limits.MaxCapParams)
            {
                throw new AicException("principalAuthorization: capability[" + i + "].parameters length "
                    + c.Parameters!.Length + ": must be 0-" + Limits.MaxCapParams);
            }
            if (ConstraintScheme == c.SchemeId)
            {
                throw new AicException("principalAuthorization: capability[" + i + "].schemeId \"" + ConstraintScheme
                    + "\": constraint scheme forbidden in capabilities");
            }
        }

        if (pa.Extensions.Count > Limits.MaxExtensionsSlots)
        {
            throw new AicException("principalAuthorization: extensions count " + pa.Extensions.Count
                + " exceeds max " + Limits.MaxExtensionsSlots);
        }
        for (int i = 0; i < pa.Extensions.Count; i++)
        {
            ExtField ext = pa.Extensions[i];
            if (ext.Critical && !ContainsOid(KnownExtensionOids, ext.ExtnId))
            {
                throw new AicException("principalAuthorization: extensions[" + i + "] has unknown critical OID " + ext.ExtnId.Id);
            }
        }

        System.Collections.Generic.IReadOnlyList<Capability> constraints = pa.AuthorizationConstraints;
        if (constraints.Count > Limits.MaxAuthorizationConstraints)
        {
            throw new AicException("principalAuthorization: authorizationConstraints count " + constraints.Count
                + " exceeds max " + Limits.MaxAuthorizationConstraints);
        }
        for (int i = 0; i < constraints.Count; i++)
        {
            Capability c = constraints[i];
            if (!ConstraintSchemesValidation.Contains(c.SchemeId))
            {
                throw new AicException("principalAuthorization: authorizationConstraints[" + i + "].schemeId \""
                    + c.SchemeId + "\": must be \"constraint\", \"constraint-v1\", or \"varwof/constraint-v1\"");
            }
            if (c.CapabilityId.Length == 0)
            {
                throw new AicException("principalAuthorization: authorizationConstraints[" + i + "].capabilityId: must not be empty");
            }
        }

        DelegationPolicy? policy = pa.Policy;
        if (policy is not null)
        {
            if (policy.AllowedMode < 0 || policy.AllowedMode > 1)
            {
                throw new AicException("principalAuthorization: delegationPolicy.allowedMode " + policy.AllowedMode
                    + ": must be 0-1");
            }
            if (policy.MaxAgents < 0 || policy.MaxAgents > 255)
            {
                throw new AicException("principalAuthorization: delegationPolicy.maxAgents " + policy.MaxAgents
                    + ": must be 0-255");
            }
        }
    }

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