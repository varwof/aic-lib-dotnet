namespace Varwof.Aic.Tests;

/// <summary>Conformance fixtures and DER vectors from the Go reference implementation.</summary>
internal static class TokenFixtures
{
    public const long Iat = 1755500000L;
    public const string PrincipalSpkiB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE44H9QvDhhiXgJ9P1JuZ6TQUHDTi0OHLvQxsM0J1QzTwi1PYliVWFEGIJJZasyRMPBeBHbb9i4W7ZngTyneoW4A==";
    public const string CaSpkiB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6vKjwdHjnm9HxgfEk7O8rYF0gTnjzzfN1TniPM1DSMoKXRqTGP26bx8vN27hTf8X76M+fdyBrTCh+yL/72lyiQ==";
    public const string ExpectedKeyHash = "AzI5g3OUET8jssmYEYgla0j6so9XAqNe9YxTubyiXAE";
    public const string ExpectedJkt = "jbWrguRSzKb1CPWiICHxQxwxqDE0viEcVOc22laSXn0";

    public const string DaTbsV2Hex = "3081bf0201020c0d6167656e743a783530392d303130190201000c08636f72702e636f6d0c087a68616e6773616e040030220c0d444154415f414e414c595349530c1176322062696e64696e6720766563746f72300d300b0c0263610c05697373756502010002020e10180f32303235303831383036353332305a04100102030405060708090a0b0c0d0e0f10a13330310420033239837394113f23b2c9981188256b48fab28f5702a35ef58c53b9bca25c01a00d300b0609608648016503040201";
    public const string DaTbsV2KeyHash = "033239837394113f23b2c9981188256b48fab28f5702a35ef58c53b9bca25c01";
}
