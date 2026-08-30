using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Varwof.Aic;

/// <summary>
/// SPIFFE identity helpers (optional integration, port of Go types/aic.go
/// SPIFFE functions).
/// </summary>
public static class Spiffe
{
    public const string Scheme = "spiffe";

    public static string BuildId(string trustDomain, string agentName)
        => "spiffe://" + trustDomain + "/agent/" + agentName;

    public static void Validate(string? id, string trustDomain)
    {
        string prefix = "spiffe://" + trustDomain + "/agent/";
        if (id is null || !id.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new AicException("spiffe: invalid ID \"" + id + "\": must start with " + prefix);
        }
        string name = id.Substring(prefix.Length);
        if (name.Length == 0)
        {
            throw new AicException("spiffe: invalid ID \"" + id + "\": agent name is empty");
        }
        if (name.Contains('/'))
        {
            throw new AicException("spiffe: invalid ID \"" + id + "\": agent name must not contain /");
        }
    }

    /// <summary>First SPIFFE URI in a certificate's SANs, or null.</summary>
    public static string? ExtractFromCert(byte[] certDer)
    {
        if (certDer is null)
        {
            return null;
        }
        try
        {
            var holder = new Org.BouncyCastle.X509.X509Certificate(certDer);
            var subjAlt = holder.GetExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectAlternativeName);
            if (subjAlt is null)
            {
                return null;
            }
            GeneralNames names = GeneralNames.GetInstance(Asn1Object.FromByteArray(subjAlt.Value.GetOctets()));
            foreach (GeneralName gn in ((System.Collections.IEnumerable)names).Cast<GeneralName>())
            {
                if (gn.TagNo == GeneralName.UniformResourceIdentifier && gn.Name != null && gn.Name.ToString() is { } v
                    && v.StartsWith("spiffe://", StringComparison.Ordinal))
                {
                    return v;
                }
            }
        }
        catch
        {
            return null;
        }
        return null;
    }

    public static bool IsAgentId(string? agentId) => agentId is not null && agentId.StartsWith("spiffe://", StringComparison.Ordinal);

    /// <summary>"spiffe://varwof.com/agent/scheduler-a" -> "scheduler-a"; identity if not SPIFFE.</summary>
    public static string ParseAgentName(string? agentId)
    {
        if (!IsAgentId(agentId))
        {
            return agentId ?? "";
        }
        int idx = agentId!.LastIndexOf('/');
        if (idx < 0)
        {
            return agentId;
        }
        return agentId!.Substring(idx + 1);
    }

    /// <summary>"spiffe://varwof.com/agent/scheduler-a" -> "varwof.com"; "" if not SPIFFE.</summary>
    public static string ParseDomain(string? agentId)
    {
        if (!IsAgentId(agentId))
        {
            return "";
        }
        string trimmed = agentId!.Substring("spiffe://".Length);
        int idx = trimmed.IndexOf('/');
        if (idx < 0)
        {
            return "";
        }
        return trimmed.Substring(0, idx);
    }
}