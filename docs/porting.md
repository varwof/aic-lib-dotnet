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

- Core library: several BouncyCastle 2.4.0 API compatibility issues remain
  (see [bc-compat.md](bc-compat.md) "Open compatibility items").
- Test project: `JwtCapMatchTest.cs` compiles; others pending the fixes above.
- **Blocked**: no .NET SDK on the development machine — cannot compile or run
  xUnit locally. Correctness verified by manual review against the Java/Go
  references.

## Next steps (once a .NET SDK is available)

1. Run all 69 Java tests against the C# port.
2. Fix remaining BouncyCastle API compatibility issues.
3. Cross-language consistency check: enum names, OID constants,
   DER/GeneralizedTime encoding.
