# AIC SDK for .NET (C#)

C# implementation of the **AI Agent Identity Certificate (AIC)** RFC drafts,
ported from the Java SDK (`aic-sdk-java`) and matching the Go reference
implementation (`varwof/types`) byte-for-byte / semantically:

- **`draft-wei-aic-identity-cert`** — X.509 certificate extension (ASN.1/DER).
- **`draft-wei-aic-jwt`** — AIC-JWT: the JSON Web Token profile.

The port targets **.NET 8.0** with **BouncyCastle.Cryptography 2.4.0** and
`System.Text.Json`. The full Java test suite (69 tests) has been ported to
xUnit, including Go cross-conformance vectors.

## Status

> **Port in progress.** The Java suite is fully green (69/69); the C# port is
> structurally complete but **cannot be compiled or run locally** (no .NET SDK
> on this machine). All test logic is ported from the Java suite and reviewed
> against the BouncyCastle 2.4.0 API by inspection only.
>
> The remaining risk is BouncyCastle API compatibility (a running list is in
> [docs/bc-compat.md](docs/bc-compat.md)). Once an SDK is available, run
> `dotnet test` and fix the flagged API differences.

## Project structure

```
aic-sdk-dotnet/
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

## License

Apache-2.0. See [LICENSE](LICENSE).
