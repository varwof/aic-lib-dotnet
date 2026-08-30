using System;
using System.Collections.Generic;
using System.Text.Json;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// AIC-JWT validation pipeline (draft-wei-aic-jwt Section 11). Mirrors Go
/// types/aicjwt/validate.go step for step, including the error-prefixed
/// diagnostics used for conformance testing.
/// </summary>
public static class Validator
{
    public const string TypOuter = "aic+jwt";
    public const string TypDa = "aic+da+jwt";
    public const string TypPa = "aic+pa+jwt";
    public const string ModeAuthorized = "authorized";
    public const string ModeRepresentative = "representative";
    public const string ConstraintScheme = "varwof/constraint-v1";
    public const int MaxLifetime = 86400;
    public const string AllowedModeRepresentative = "representative_allowed";
    public const int MaxTokenSize = 64 * 1024;
    public const int MaxParamsSize = 512;

    /// <summary>Evaluates a request capability for a scheme (fail-closed for unknown schemes).</summary>
    public delegate void CapabilityPlugin(Claims.Capability req, Constraints.RequestContext ctx);

    /// <summary>Validates a Token Status List reference.</summary>
    public delegate void StatusChecker(Claims.StatusRef reference);

    /// <summary>Configures the validation pipeline.</summary>
    public sealed class VerifyOptions
    {
        public DateTime? Now { get; set; }
        public string? ExpectedIssuer { get; set; }
        public List<string>? ExpectedAudience { get; set; }
        public Dictionary<string, byte[]>? IssuerSpki { get; set; }
        public KeyHash.PrincipalKeyMaterial? PrincipalMaterial { get; set; }
        public Dictionary<string, byte[]>? PrincipalJwks { get; set; }
        public byte[]? PresenterSpki { get; set; }
        public Claims.Capability? RequestCapability { get; set; }
        public Constraints.RequestContext? RequestContext { get; set; }
        public bool ConstraintStrict { get; set; }
        public Dictionary<string, CapabilityPlugin>? CapabilityPlugins { get; set; }
        public StatusChecker? StatusChecker { get; set; }
        public NonceStore.IStore? NonceStore { get; set; }
        public bool RejectDepthGt1 { get; set; }
        public bool RequireJtiNonceMatch { get; set; }
        public Claims.PaClaims? Pa { get; set; }
    }

    /// <summary>Outcome of the validation pipeline.</summary>
    public sealed record Decision(
        bool Permit,
        string Actor,
        string Principal,
        IReadOnlyList<Claims.Capability>? Capabilities,
        IReadOnlyList<string>? Notes)
    {
        public Decision(bool permit, string actor, string? principal,
            IEnumerable<Claims.Capability>? capabilities, IEnumerable<string>? notes)
            : this(permit, actor, principal ?? "", capabilities is null ? null : new List<Claims.Capability>(capabilities),
                notes is null ? null : new List<string>(notes))
        {
        }
    }

    /// <summary>Executes the 11-step pipeline of draft Section 11.</summary>
    public static Decision Validate(string token, VerifyOptions opts)
    {
        opts ??= new VerifyOptions();
        DateTime now = opts.Now ?? DateTime.UtcNow;

        // ---- Step 0: size bound ----
        if (token.Length > MaxTokenSize)
        {
            throw new AicException("step0: token size " + token.Length + " exceeds max " + MaxTokenSize);
        }

        // ---- Step 1: parse + verify the outer JWS ----
        byte[][] parts;
        try
        {
            parts = Jws.ParseCompact(token);
        }
        catch (AicException ex)
        {
            throw new AicException("step1: " + ex.Message);
        }
        byte[] hb = parts[0];
        byte[] pb = parts[1];
        if (JwtJson.HasDuplicateKeys(hb))
        {
            throw new AicException("step1: outer header contains duplicate JSON member names");
        }
        if (JwtJson.HasDuplicateKeys(pb))
        {
            throw new AicException("step1: outer payload contains duplicate JSON member names");
        }
        Claims.Header hdr;
        try
        {
            hdr = ParseHeader(hb);
        }
        catch (AicException ex)
        {
            throw new AicException("step1: outer header malformed: " + ex.Message);
        }
        // ---- Step 2: header checks ----
        CheckHeader(hdr, TypOuter);
        byte[]? issuerSpki = opts.IssuerSpki is null ? null : HdrKid(opts.IssuerSpki, hdr.Kid);
        if (issuerSpki is null)
        {
            throw new AicException("step2: unknown issuer kid \"" + hdr.Kid + "\"");
        }
        var issuerKey = SigAlgorithms.PublicKeyFromSpki(issuerSpki);
        if (issuerKey is null)
        {
            throw new AicException("step2: issuer key \"" + hdr.Kid + "\" not importable");
        }
        try
        {
            Jws.VerifyCompact(token, hdr.Alg!, issuerKey);
        }
        catch (AicException ex)
        {
            throw new AicException("step1: outer signature invalid: " + ex.Message);
        }

        // ---- Step 1 (cont.): parse payload after signature verified (matches Go) ----
        Claims.OuterClaims outer;
        try
        {
            outer = ParseOuter(pb);
        }
        catch (AicException ex)
        {
            throw new AicException("step1: outer payload malformed: " + ex.Message);
        }
        CheckOuterRequired(outer);

        // ---- Step 3: time checks ----
        try
        {
            CheckTime(outer, now);
        }
        catch (AicException ex)
        {
            throw new AicException("step3: " + ex.Message);
        }

        // ---- Step 4: DA validation ----
        Claims.DaClaims? da = null;
        if (!string.IsNullOrEmpty(outer.Da))
        {
            try
            {
                da = ValidateDa(outer.Da, outer, opts);
            }
            catch (AicException ex)
            {
                throw new AicException("step4: " + ex.Message);
            }
        }
        else if (ModeRepresentative == outer.Aic?.DelegationMode)
        {
            throw new AicException("step4: representative mode requires a DA JWT");
        }
        else if (outer.Exp - outer.Iat > MaxLifetime)
        {
            throw new AicException("step3: lightweight profile lifetime " + (outer.Exp - outer.Iat)
                + " exceeds max " + MaxLifetime);
        }

        // ---- Step 5: consistency checks ----
        if (da is not null)
        {
            try
            {
                CheckConsistency(outer, da);
            }
            catch (AicException ex)
            {
                throw new AicException("step5: " + ex.Message);
            }
        }

        // ---- Step 6: PA check (representative) ----
        if (ModeRepresentative == outer.Aic?.DelegationMode)
        {
            try
            {
                CheckPa(outer, opts);
            }
            catch (AicException ex)
            {
                throw new AicException("step6: " + ex.Message);
            }
        }

        // ---- Step 7: constraint evaluation ----
        List<string> notes;
        try
        {
            notes = Constraints.EvaluateConstraints(
                outer.Aic!.Constraints, opts.RequestContext, opts.ConstraintStrict);
        }
        catch (AicException ex)
        {
            throw new AicException("step7: aic.constraints: " + ex.Message);
        }

        // ---- Step 8: delegation depth check ----
        try
        {
            CheckDepth(outer.Aic, opts);
        }
        catch (AicException ex)
        {
            throw new AicException("step8: " + ex.Message);
        }

        // ---- Step 9: capability evaluation ----
        if (opts.RequestCapability is not null)
        {
            if (!CapMatch.MatchCapabilities(outer.Aic.Capabilities, opts.RequestCapability))
            {
                throw new AicException("step9: capability " + opts.RequestCapability.Scheme + ":"
                    + opts.RequestCapability.Id + " not allowed by aic.capabilities");
            }
            CapabilityPlugin? plugin = opts.CapabilityPlugins is null ? null
                : CapabilityPluginOf(opts.CapabilityPlugins, opts.RequestCapability.Scheme);
            if (plugin is null)
            {
                throw new AicException("step9: unknown capability scheme \""
                    + opts.RequestCapability.Scheme + "\" (fail-closed)");
            }
            try
            {
                plugin(opts.RequestCapability, opts.RequestContext ?? new Constraints.RequestContext());
            }
            catch (AicException ex)
            {
                throw new AicException("step9: scheme plugin denies " + opts.RequestCapability.Scheme + ":"
                    + opts.RequestCapability.Id + ": " + ex.Message);
            }
        }

        // ---- Step 10: status check ----
        if (outer.Status is not null)
        {
            if (opts.StatusChecker is null)
            {
                throw new AicException("step10: status claim present but no status checker configured");
            }
            try
            {
                opts.StatusChecker(outer.Status);
            }
            catch (AicException ex)
            {
                throw new AicException("step10: token status check failed: " + ex.Message);
            }
        }

        // ---- issuer / audience / presenter binding ----
        if (!string.IsNullOrEmpty(opts.ExpectedIssuer) && opts.ExpectedIssuer != outer.Iss)
        {
            throw new AicException("iss \"" + outer.Iss + "\" does not match expected issuer \""
                + opts.ExpectedIssuer + "\"");
        }
        if (opts.ExpectedAudience is { Count: > 0 })
        {
            bool matched = false;
            foreach (string a in opts.ExpectedAudience)
            {
                if (outer.Aud!.Contains(a))
                {
                    matched = true;
                    break;
                }
            }
            if (!matched)
            {
                throw new AicException("aud " + outer.Aud + " does not include any of "
                    + string.Join(", ", opts.ExpectedAudience) + " (audience confusion)");
            }
        }
        if (opts.PresenterSpki is not null)
        {
            if (outer.Cnf is null || string.IsNullOrEmpty(outer.Cnf.Jkt))
            {
                throw new AicException("cnf claim required but missing");
            }
            string thumb = KeyHash.KeyHashOf(opts.PresenterSpki, "jkt");
            if (thumb != outer.Cnf.Jkt)
            {
                throw new AicException("cnf: presenter key does not match token cnf.jkt (token theft)");
            }
        }

        // ---- Decision ----
        string actor = outer.Sub ?? "";
        string principal = outer.Aic!.Principal!.Id ?? "";
        if (ModeRepresentative == outer.Aic.DelegationMode)
        {
            actor = principal;
        }
        return new Decision(true, actor, principal, outer.Aic.Capabilities, notes);
    }

    private static byte[]? HdrKid(Dictionary<string, byte[]> keys, string? kid)
        => kid is not null && keys.TryGetValue(kid, out byte[]? v) ? v : null;

    private static CapabilityPlugin? CapabilityPluginOf(Dictionary<string, CapabilityPlugin> plugins, string? scheme)
        => scheme is not null && plugins.TryGetValue(scheme, out CapabilityPlugin? p) ? p : null;

    /// <summary>Validates a JOSE header against the expected typ and algorithm allowlist.</summary>
    public static void CheckHeader(Claims.Header h, string expectedTyp)
    {
        if (expectedTyp != h.Typ)
        {
            throw new AicException("unexpected typ \"" + h.Typ + "\" (expected \"" + expectedTyp + "\")");
        }
        if (string.IsNullOrEmpty(h.Alg) || "none" == h.Alg)
        {
            throw new AicException("alg missing or none");
        }
        if (!Jws.AllowedAlgs.Contains(h.Alg))
        {
            throw new AicException("alg \"" + h.Alg + "\" not in allowlist");
        }
        if (string.IsNullOrEmpty(h.Kid))
        {
            throw new AicException("kid required");
        }
        if (h.Crit is not null)
        {
            foreach (string c in h.Crit)
            {
                throw new AicException("unsupported critical header \"" + c + "\"");
            }
        }
    }

    private static void CheckOuterRequired(Claims.OuterClaims o)
    {
        if (string.IsNullOrEmpty(o.Iss))
        {
            throw new AicException("iss required");
        }
        if (string.IsNullOrEmpty(o.Sub) || o.Sub.Length > 256)
        {
            throw new AicException("sub (agentId) required, 1..256 chars");
        }
        if (o.Aud is null || o.Aud.Size == 0)
        {
            throw new AicException("aud required");
        }
        if (o.Iat == 0 || o.Exp == 0 || o.Exp <= o.Iat)
        {
            throw new AicException("iat/exp required and exp must be after iat");
        }
        if (string.IsNullOrEmpty(o.Jti))
        {
            throw new AicException("jti required");
        }
        if (o.Cnf is null || string.IsNullOrEmpty(o.Cnf.Jkt))
        {
            throw new AicException("cnf required");
        }
        if (o.Aic is null)
        {
            throw new AicException("aic claim required");
        }
        if (o.Aic.Ver != 1)
        {
            throw new AicException("aic.ver must be 1");
        }
        Claims.Principal? p = o.Aic.Principal;
        if (p is null || string.IsNullOrEmpty(p.Realm) || p.Realm.Length > 128
            || string.IsNullOrEmpty(p.Id) || p.Id.Length > 256
            || string.IsNullOrEmpty(p.KeyHash))
        {
            throw new AicException("aic.principal realm/id/key_hash required within size limits");
        }
        string alg = string.IsNullOrEmpty(p.HashAlg) ? "sha-256" : p.HashAlg;
        if (!KeyHash.SupportedHashAlgs.ContainsKey(alg))
        {
            throw new AicException("unsupported aic.principal.hash_alg \"" + p.HashAlg + "\"");
        }
        if (ModeAuthorized != o.Aic.DelegationMode && ModeRepresentative != o.Aic.DelegationMode)
        {
            throw new AicException("aic.delegation_mode must be \"" + ModeAuthorized
                + "\" or \"" + ModeRepresentative + "\"");
        }
        if (o.Aic.Capabilities is null || o.Aic.Capabilities.Count < 1 || o.Aic.Capabilities.Count > 256)
        {
            throw new AicException("aic.capabilities must contain 1..256 entries");
        }
        foreach (Claims.Capability c in o.Aic.Capabilities)
        {
            if (JwtJson.CompactLength(c.Params) > MaxParamsSize)
            {
                throw new AicException("aic.capabilities params exceed " + MaxParamsSize + " bytes");
            }
        }
        if (o.Aic.Constraints is not null && o.Aic.Constraints.Count > 32)
        {
            throw new AicException("aic.constraints must not exceed 32 entries");
        }
        if (o.Aic.Constraints is not null)
        {
            foreach (Claims.Capability c in o.Aic.Constraints)
            {
                if (JwtJson.CompactLength(c.Params) > MaxParamsSize)
                {
                    throw new AicException("aic.constraints params exceed " + MaxParamsSize + " bytes");
                }
            }
        }
        if (o.Aic.Extensions is not null && o.Aic.Extensions.Count > 32)
        {
            throw new AicException("aic.extensions must not exceed 32 entries");
        }
    }

    private static void CheckTime(Claims.OuterClaims o, DateTime now)
    {
        long nowUnix = new DateTimeOffset(now.ToUniversalTime()).ToUnixTimeSeconds();
        if (o.Nbf is not null && nowUnix < o.Nbf)
        {
            throw new AicException("token not yet valid (nbf)");
        }
        if (nowUnix > o.Exp)
        {
            throw new AicException("token expired");
        }
    }

    private static void CheckDaRequired(Claims.DaClaims d)
    {
        if (d.Ver != 1)
        {
            throw new AicException("DA ver must be 1");
        }
        if (string.IsNullOrEmpty(d.AgentId) || d.AgentId.Length > 256)
        {
            throw new AicException("DA agent_id required, 1..256 chars");
        }
        if (d.Principal is null || string.IsNullOrEmpty(d.Principal.Realm)
            || string.IsNullOrEmpty(d.Principal.Id)
            || string.IsNullOrEmpty(d.Principal.KeyHash))
        {
            throw new AicException("DA principal required");
        }
        if (d.Reason is null || string.IsNullOrEmpty(d.Reason.Code)
            || string.IsNullOrEmpty(d.Reason.Desc))
        {
            throw new AicException("DA reason.code and reason.desc required");
        }
        if (d.Capabilities is null || d.Capabilities.Count < 1 || d.Capabilities.Count > 256)
        {
            throw new AicException("DA capabilities must contain 1..256 entries");
        }
        foreach (Claims.Capability c in d.Capabilities)
        {
            if (JwtJson.CompactLength(c.Params) > MaxParamsSize)
            {
                throw new AicException("DA capabilities params exceed " + MaxParamsSize + " bytes");
            }
        }
        if (ModeAuthorized != d.DelegationMode && ModeRepresentative != d.DelegationMode)
        {
            throw new AicException("DA delegation_mode invalid");
        }
        if (d.Constraints is not null && d.Constraints.Count > 32)
        {
            throw new AicException("DA constraints must not exceed 32 entries");
        }
        if (d.Constraints is not null)
        {
            foreach (Claims.Capability c in d.Constraints)
            {
                if (JwtJson.CompactLength(c.Params) > MaxParamsSize)
                {
                    throw new AicException("DA constraints params exceed " + MaxParamsSize + " bytes");
                }
            }
        }
        if (d.RequestedLifetime < 1 || d.RequestedLifetime > MaxLifetime)
        {
            throw new AicException("DA requested_lifetime must be in 1.." + MaxLifetime);
        }
        if (d.Ts == 0)
        {
            throw new AicException("DA ts required");
        }
        if (string.IsNullOrEmpty(d.Nonce))
        {
            throw new AicException("DA nonce required");
        }
    }

    /// <summary>Validates a DA JWT in isolation: header, claims, signature, binding, nonce.</summary>
    public static Claims.DaClaims ValidateDa(string daToken, VerifyOptions opts)
    {
        if (daToken.Length > MaxTokenSize)
        {
            throw new AicException("DA token size " + daToken.Length + " exceeds max " + MaxTokenSize);
        }
        byte[][] parts;
        try
        {
            parts = Jws.ParseCompact(daToken);
        }
        catch (AicException ex)
        {
            throw new AicException("DA parse: " + ex.Message);
        }
        if (JwtJson.HasDuplicateKeys(parts[0]))
        {
            throw new AicException("DA header contains duplicate JSON member names");
        }
        if (JwtJson.HasDuplicateKeys(parts[1]))
        {
            throw new AicException("DA payload contains duplicate JSON member names");
        }
        Claims.Header hdr;
        try
        {
            hdr = ParseHeader(parts[0]);
        }
        catch (AicException ex)
        {
            throw new AicException("DA header malformed: " + ex.Message);
        }
        CheckHeader(hdr, TypDa);
        Claims.DaClaims da;
        try
        {
            da = JsonSerializer.Deserialize<Claims.DaClaims>(parts[1], JwtJson.WireOptions)!;
        }
        catch (Exception ex)
        {
            throw new AicException("DA payload malformed: " + ex.Message);
        }
        CheckDaRequired(da);
        byte[] pub = ResolvePrincipalSpki(da.Principal!, hdr.Kid, opts);
        try
        {
            Jws.VerifyCompact(daToken, hdr.Alg!, SigAlgorithms.PublicKeyFromSpki(pub)!);
        }
        catch (AicException ex)
        {
            throw new AicException("DA signature invalid: " + ex.Message);
        }
        string alg = string.IsNullOrEmpty(da.Principal!.HashAlg) ? "sha-256" : da.Principal.HashAlg;
        string binding = KeyHash.KeyHashOf(pub, alg);
        if (binding != da.Principal.KeyHash)
        {
            throw new AicException("DA principal key_hash mismatch");
        }
        byte[]? nonceBytes;
        try
        {
            nonceBytes = Jws.B64uDecode(da.Nonce!);
        }
        catch (AicException)
        {
            nonceBytes = null;
        }
        if (nonceBytes is null || nonceBytes.Length != 32)
        {
            throw new AicException("DA nonce must be the base64url of 32 bytes");
        }
        if (opts.NonceStore is not null)
        {
            try
            {
                opts.NonceStore.CheckAndAdd(da.Nonce!);
            }
            catch (NonceStore.NonceReuseException ex)
            {
                throw new AicException("DA nonce reuse: " + ex.Message);
            }
        }
        return da;
    }

    internal static Claims.DaClaims ValidateDa(string daToken, Claims.OuterClaims outer, VerifyOptions opts)
    {
        Claims.DaClaims da = ValidateDa(daToken, opts);
        if (opts.RequireJtiNonceMatch && outer.Jti != da.Nonce)
        {
            throw new AicException("outer jti does not match DA nonce");
        }
        if (outer.Exp - outer.Iat > da.RequestedLifetime)
        {
            throw new AicException("token lifetime " + (outer.Exp - outer.Iat)
                + " exceeds DA requested_lifetime " + da.RequestedLifetime);
        }
        return da;
    }

    private static byte[] ResolvePrincipalSpki(Claims.Principal p, string? kid, VerifyOptions opts)
    {
        if (opts.PrincipalMaterial is not null)
        {
            if (!string.IsNullOrEmpty(kid) && opts.PrincipalMaterial.JwkSpki is not null
                && opts.PrincipalMaterial.JwkSpki.TryGetValue(kid, out byte[]? jwks))
            {
                return jwks;
            }
            try
            {
                return opts.PrincipalMaterial.LookupByBinding(p);
            }
            catch (AicException)
            {
                // fall through to online JWKS
            }
        }
        if (opts.PrincipalJwks is not null && !string.IsNullOrEmpty(kid)
            && opts.PrincipalJwks.TryGetValue(kid, out byte[]? spki))
        {
            return spki;
        }
        throw new AicException("principal key not resolvable (kid \"" + kid + "\")");
    }

    private static void CheckConsistency(Claims.OuterClaims o, Claims.DaClaims da)
    {
        if (da.AgentId != o.Sub)
        {
            throw new AicException("DA agent_id \"" + da.AgentId + "\" != outer sub \"" + o.Sub + "\"");
        }
        if (!JwtJson.JsonEqual(da.Principal, o.Aic!.Principal))
        {
            throw new AicException("DA principal != outer aic.principal");
        }
        if (da.DelegationMode != o.Aic.DelegationMode)
        {
            throw new AicException("DA delegation_mode != outer aic.delegation_mode");
        }
        if (!JwtJson.JsonEqual(da.Capabilities, o.Aic.Capabilities))
        {
            throw new AicException("DA capabilities != outer aic.capabilities");
        }
        if (!JwtJson.JsonEqual(da.Constraints, o.Aic.Constraints))
        {
            throw new AicException("DA constraints != outer aic.constraints");
        }
    }

    private static void CheckPa(Claims.OuterClaims o, VerifyOptions opts)
    {
        Claims.PaClaims? pa = opts.Pa;
        if (pa is null)
        {
            throw new AicException("representative mode requires PrincipalAuthorization material");
        }
        if (pa.Ver != 1)
        {
            throw new AicException("PA ver must be 1");
        }
        if (!JwtJson.JsonEqual(pa.Principal, o.Aic!.Principal))
        {
            throw new AicException("PA principal != outer aic.principal");
        }
        if (pa.DelegationPolicy is null || AllowedModeRepresentative != pa.DelegationPolicy.AllowedMode)
        {
            throw new AicException("delegation policy does not allow representative mode");
        }
        foreach (Claims.Capability c in o.Aic.Capabilities!)
        {
            if (!CapMatch.CapabilitySubset(c, pa.Grants))
            {
                throw new AicException("capability " + c.Scheme + ":" + c.Id + " not within P_grants");
            }
        }
        if (pa.Grants is not null)
        {
            foreach (Claims.Capability g in pa.Grants)
            {
                if (JwtJson.CompactLength(g.Params) > MaxParamsSize)
                {
                    throw new AicException("PA grants params exceed " + MaxParamsSize + " bytes");
                }
            }
        }
        if (pa.Constraints is not null)
        {
            foreach (Claims.Capability c in pa.Constraints)
            {
                if (JwtJson.CompactLength(c.Params) > MaxParamsSize)
                {
                    throw new AicException("PA constraints params exceed " + MaxParamsSize + " bytes");
                }
            }
        }
        Constraints.EvaluateConstraints(pa.Constraints, opts.RequestContext, opts.ConstraintStrict);
    }

    private static void CheckDepth(Claims.AicClaims a, VerifyOptions opts)
    {
        int chainDepth = a.ChainDepth ?? 0;
        int maxDepth = a.MaxDepth ?? 0;
        if (chainDepth < 0 || chainDepth > 255)
        {
            throw new AicException("chain_depth out of range");
        }
        if (maxDepth < 0 || maxDepth > 255)
        {
            throw new AicException("max_depth out of range");
        }
        if (chainDepth > maxDepth)
        {
            throw new AicException("chain_depth " + chainDepth + " exceeds max_depth " + maxDepth);
        }
        if (opts.RejectDepthGt1 && maxDepth > 1)
        {
            throw new AicException("max_depth " + maxDepth + " exceeds recommended limit 1");
        }
    }

    private static Claims.Header ParseHeader(byte[] raw)
    {
        try
        {
            return JsonSerializer.Deserialize<Claims.Header>(raw, JwtJson.WireOptions)!;
        }
        catch (Exception ex)
        {
            throw new AicException(ex.Message);
        }
    }

    private static Claims.OuterClaims ParseOuter(byte[] raw)
    {
        try
        {
            return JsonSerializer.Deserialize<Claims.OuterClaims>(raw, JwtJson.WireOptions)!;
        }
        catch (Exception ex)
        {
            throw new AicException(ex.Message);
        }
    }
}