namespace Varwof.Aic;

/// <summary>
/// How an agent may be delegated. Mirrors types/delegation_mode.go.
/// </summary>
public enum DelegationMode
{
    /// <summary>delegated directly by the principal or by chain, without representation calls.</summary>
    Authorized = 0,

    /// <summary>the agent may act as a representative and exercise the principal's identity.</summary>
    Representative = 1
}

public static class DelegationModes
{
    public static bool IsRepresentative(this DelegationMode m) => m == DelegationMode.Representative;

    public static DelegationMode FromValue(int v) => v switch
    {
        0 => DelegationMode.Authorized,
        1 => DelegationMode.Representative,
        _ => throw new AicException("invalid delegation mode: " + v)
    };

    public static string ToWire(this DelegationMode m)
        => m == DelegationMode.Representative ? "representative" : "authorized";
}