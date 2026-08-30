namespace Varwof.Aic;

/// <summary>
/// Hard limits governing AIC policy evaluation and structure.
/// Constants mirror types/limits.go and the draft recommendations so
/// the Java and C# ports reject identical inputs as the Go reference.
/// </summary>
public static class Limits
{
    public const int MaxCapabilities = 256;
    public const int MaxAuthorizationConstraints = 32;
    public const int MaxExtensionsSlots = 32;
    public const int MaxGrantEntries = 256;
    public const int MaxConstraintParams = 512;
    public const int MaxCapParams = 4096;
    public const int MaxNonceLen = 32;
    public const int MaxRequestedLifetime = 86400;
    public const int MinRequestedLifetime = 3600;
    public const int MaxRecommendedCertDerSize = 12 * 1024;
    public const int PrincipalKeyHashLen = 32;
}