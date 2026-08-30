# AIC SDK for .NET — Documentation

C# port of the AIC protocol family (X.509/ASN.1 + JWT profiles), matching the
Java SDK and the Go reference implementation.

## Status summary

- Java source suite: **69/69 green** (DER vectors, JWS, JWT validator,
  capability matching, cert build/parse, Go conformance).
- C# port: **complete** — built and tested on .NET SDK 8.0.424 (linux-x64),
  **69/69 tests pass** with 0 warnings / 0 errors (TreatWarningsAsErrors).
- See [bc-compat.md](bc-compat.md) for the verified compatibility record and
  [porting.md](porting.md) for the work log.

## Layout

| Path | Contents |
|------|----------|
| `src/Varwof.Aic/` | core library (net8.0, nullable enabled, warnings-as-errors) |
| `src/Varwof.Aic/Cert/` | X.509 certificate builders / extension extraction |
| `src/Varwof.Aic/Jwt/` | AIC-JWT: validator, JWS, claims, matcher |
| `tests/Varwof.Aic.Tests/` | xUnit port of the 69 Java tests |

## Getting started

```sh
dotnet restore
dotnet build
dotnet test
```

## API surface

Mirrors the Java SDK class-for-class (`Aic`/`AicBuilder`, `AicValidator`,
`DelegationAuthCrypto`, `SigAlgorithms`, `Oids`, `Der`, `CapabilityMatcher`,
`jwt.Validator`, ...). Key differences from Java:

- BouncyCastle `.NET` API types (`AsymmetricKeyParameter`, `DerObjectIdentifier`,
  `Org.BouncyCastle.X509.X509Certificate`, `ISignatureFactory`).
- Nullable reference types enabled; `TreatWarningsAsErrors` in the src project.

## Documents

- [bc-compat.md](bc-compat.md) — BouncyCastle 2.4.0 API compatibility checklist
- [porting.md](porting.md) — porting progress log
