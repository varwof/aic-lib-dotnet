# AIC SDK for .NET (C#)

> **Maintainers wanted.** This is an open, community-oriented SDK. We welcome
> active maintainers for review, porting, packaging, and platform testing.
> See [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) (org-wide) and the
> "Contributing" section below.

C# implementation of the **AI Agent Identity Certificate (AIC)** RFC drafts,
ported from the Java library (`aic-lib-java`) and matching the Go reference
implementation (`varwof/types`) byte-for-byte / semantically:

- **`draft-wei-aic-identity-cert`** — X.509 certificate extension (ASN.1/DER).
- **`draft-wei-aic-jwt`** — AIC-JWT: the JSON Web Token profile.

The port targets **.NET 8.0** with **BouncyCastle.Cryptography 2.4.0** and
`System.Text.Json`. The full Java test suite (69 tests) has been ported to
xUnit, including Go cross-conformance vectors.

## Why AIC?

An ordinary X.509 certificate proves *who* an entity is; it says nothing about
*what it is allowed to do*. AI agents act on behalf of humans, often across
organizational boundaries, so a relying party needs to know not just the
agent's identity but also: which human (principal) delegated to this agent,
what capabilities were granted and under what constraints, and that the grant
is fresh and cannot be replayed. AIC (Authorization in Certificates) encodes
that evidence into the certificate itself (X.509v3 extension) or into a JWT
profile, so a gateway can decide permission locally and offline.

## Language matrix

AIC is implemented in five languages, all byte-compatible with the Go
reference:

| Language | Repository | Status |
|----------|-----------|--------|
| Go (reference) | [varwof/types](https://github.com/varwof/types) | complete |
| TypeScript | [varwof/aic-jwt](https://github.com/varwof/aic-jwt) | complete (18 tests) |
| C / OpenSSL | [varwof/openaic](https://github.com/varwof/openaic) | complete (13 tests) |
| Java | [varwof/aic-lib-java](https://github.com/varwof/aic-lib-java) | complete (69 tests) |
| C# | [**this repo (aic-lib-dotnet)**](https://github.com/varwof/aic-lib-dotnet) | complete (69 tests) |

## Status

> **Complete.** Verified on .NET SDK 8.0.424 (linux-x64): the full xUnit suite
> passes **69/69** (DER vectors, JWS round-trips, JWT validator, capability
> matching, cert build/parse, Go cross-conformance), with
> `TreatWarningsAsErrors` enabled (0 warnings, 0 errors).
>
> The BouncyCastle.Cryptography 2.4.0 API divergences flagged during the port
> were resolved by build-time fixes; see [docs/bc-compat.md](docs/bc-compat.md)
> for the final record and [docs/porting.md](docs/porting.md) for the log.

## Project structure

```
aic-lib-dotnet/
├── Varwof.Aic.sln                  solution
├── src/Varwof.Aic/                 core library (net8.0)
│   ├── Aic.cs / AicBuilder         AIC model + builder
│   ├── AicValidator.cs             spec validation + constraint evaluation
│   ├── PrincipalUid.cs, Capability.cs, Reason.cs, ExtField.cs
│   ├── DelegationAuthTbs.cs, DelegationAuthorization.cs
│   ├── DelegationAuthCrypto.cs     DA sign/verify
│   ├── SigAlgorithms.cs, HashAlgorithms.cs, Ecdsa.cs, Oids.cs, Der.cs
│   ├── CapabilityMatcher.cs, CapabilityRule.cs, CapMatch (Jwt/)
│   ├── DelegationDepthControl.cs, DelegationPolicy.cs, Limits.cs, Spiffe.cs
│   ├── PrincipalAuthorization.cs, PrincipalAuthorizationValidator.cs
│   ├── Cert/                       AicCertificateBuilder, AicCertificates
│   └── Jwt/                        Validator, Jws, Claims, Constraints,
│                                   KeyHash, NonceStore, CapMatch
└── tests/Varwof.Aic.Tests/         xUnit port of the 69 Java tests
```

## Requirements

- .NET 8 SDK
- NuGet packages: `BouncyCastle.Cryptography` 2.4.0, `System.Text.Json` 8.0.5
  (restored automatically)

## Build & test

```sh
dotnet restore
dotnet build           # TreatWarningsAsErrors in the src project
dotnet test            # run the xUnit suite
```

Expected: `Passed! - Failed: 0, Passed: 69, Skipped: 0, Total: 69`
(verified on .NET SDK 8.0.424, linux-x64).

## Usage (API surface mirrors the Java SDK)

```csharp
using Varwof.Aic;

var aic = Aic.Builder()
    .AgentId("agent-7")
    .PrincipalUid(new PrincipalUid("acme", "alice", keyHash, null))
    .Capability(new Capability("tt", "smart-device"))
    .Constraint(new Capability("constraint", "max-concurrent",
                               Encoding.UTF8.GetBytes("{\"max\":3}")))
    .DelegationMode(DelegationMode.Authorized)
    .Build();

AicValidator.Validate(aic);
byte[] der = aic.Encode();
var parsed = Aic.Parse(der);

// DA sign/verify
var da = DelegationAuthCrypto.Sign(tbs, principalKey);
bool ok = DelegationAuthCrypto.Verify(tbs, da, principalPublicKey);

// AIC-JWT
var d = Jwt.Validator.Validate(token, new Jwt.Validator.VerifyOptions()
    .WithIssuerKeys(...));
```

## Documentation

- [docs/index.md](docs/index.md) — overview & status
- [docs/bc-compat.md](docs/bc-compat.md) — BouncyCastle 2.4.0 compatibility checklist
- [docs/porting.md](docs/porting.md) — porting progress log

## Contributing

This SDK is community-maintained. You do not need to be a core team member
to contribute:

- **Report bugs / request features** — open an issue; bug reports do not
  require a contributor agreement.
- **Send a patch** — code contributions go through pull requests and require a
  DCO sign-off (a `Signed-off-by` line in the commit message). The org-wide
  process is in [CONTRIBUTING.md](../../.github/CONTRIBUTING.md).
- **Become a maintainer** — after a few merged PRs, ask for collaborator
  access; regular reviewers are invited to take ownership of this SDK.

## License

Apache-2.0. See [LICENSE](LICENSE).
