# Porting log

Progress history of the C# port from the Java SDK. Each entry reflects work
done; the canonical "where we are" state lives in
[bc-compat.md](bc-compat.md) and the top of the README.

## Completed

- **`SigAlgorithms.cs`**: extended with `IsSupported`, `ForKey`, `Sign`,
  `Verify` (DER signatures: ECDSA DER, RSA PKCS1, PSS salt=32, Ed25519 raw);
  `DigestForOid` helper.
- **`DelegationAuthCrypto.cs`**: extended with `Sign(tbs,key,sigOid)`,
  `Sign(tbs,key)` overload, `ComputeSignature`, `Verify(tbs,da,principalKey)`,
  `VerifyAic(aic,principalKey)`.
- **`AicCertificateBuilder.cs`**: fixed `ContentSignerFor` EC key check to
  match only `ECPrivateKeyParameters`.
- **Python fixtures**: generated `DerVectors.cs` and `TokenFixtures.cs` from
  the Go vectors.
- **Test files written**: `TestHex.cs`, `DerVectorsTest.cs`,
  `CapabilityMatchTest.cs`, `AicValidatorTest.cs`,
  `DelegationAuthCryptoTest.cs`, `CertTest.cs`, `JwsTest.cs`,
  `JwtValidatorTest.cs`, `GoConformanceTest.cs`, `JwtCapMatchTest.cs`.
- **API renames** (see [bc-compat.md](bc-compat.md) "Renames already applied").

## Current

- **Complete.** Built and tested on .NET SDK 8.0.424 (linux-x64).
- `dotnet build`: 0 warnings / 0 errors (TreatWarningsAsErrors).
- `dotnet test`: **69/69 passed** — DER vectors, JWS round-trips, JWT
  validator, capability matching, cert build/parse, Go cross-conformance.

## Status of distribution

The library is buildable and testable from source on .NET 8. CI configuration,
NuGet packaging, and Windows/macOS runner coverage are tracked as GitHub
issues and will be added over time.
