# BouncyCastle.Cryptography 2.4.0 compatibility checklist

The C# port targets BouncyCastle.Cryptography **2.4.0** (the .NET
re-branded fork; note the Java-style `BouncyCastle.Cryptography` naming and the
`X509Certificate` vs `X509CertificateHolder` differences). This list tracks
every known API divergence between the Java source and the .NET 2.4.0 API.

## Renames already applied

- `Asn1ObjectIdentifier` → `DerObjectIdentifier`.
- `X509CertificateHolder` → `Org.BouncyCastle.X509.X509Certificate`
  (no `X509CertificateHolder` in 2.4.0).
- `SigAlgorithms.Ed25519()` → `Ed25519Algorithm()` (name collided with the
  `const string Ed25519`).
- `CapabilityRule.Deny()` → `DenyRule()` (collided with a property).
- `Der.Der()` → `DerEncode()` (all 13 call sites).
- Removed duplicate `HasAicExtension(Extensions?)` overload (redundant with the
  `X509Certificate?` overload).
- `var out` → `var result` in `Aic.cs`, `DelegationAuthTbs.cs`,
  `PrincipalAuthorization.cs` (`out` is a keyword).
- Added `using System.Text.Json;` in `CapMatch.cs` (`JsonValueKind`).

## Open compatibility items (need `dotnet build` to confirm/fix)

### Core library (`src/Varwof.Aic/`)

- `AsymmetricKeyParameter.AlgorithmName` — **not available**; use OID-based
  key-type detection instead.
- `X509v3CertificateBuilder` / `X509Extension` constructor / `BasicConstraints`
  / `KeyUsage` / `SubjectAlternativeName` — verify the 2.4.0 shapes.
- `AlgorithmIdentifier` — prefer 1-arg or 2-arg constructors over the 3-arg one.
- `BigInteger.Value` — not available; use `ValueOf` / `IntValue`.
- `Asn1TaggedObject.GetObject()` — obsolete; use the no-arg `GetObject()`.
- `GeneralNames` iteration — use `.Cast<GeneralName>()`.
- `string.IsEmpty()` — use `string.IsNullOrEmpty()`.
- `ParametersWithRandom` — pattern matching shape may differ.
- `IDigest` → `IDsaKCalculator` conversion — may be a false positive.

### Test project (`tests/Varwof.Aic.Tests/`)

- `JwtCapMatchTest.cs` compiles and runs.
- Other tests have namespace/reference issues due to the BouncyCastle API
  differences above.

## When an SDK becomes available

1. `dotnet build` and fix each item above.
2. `dotnet test` — the 69 ported tests must mirror the Java results.
3. Cross-check enum names, OID constants, DER/GeneralizedTime encoding against
   the Java suite (`aic-sdk-java/src/test/...`).
