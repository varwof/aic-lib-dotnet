using System;

namespace Varwof.Aic;

/// <summary>
/// Signals an encoding/decoding/validation problem in an AIC structure.
/// Mirrors the semantics of the Go reference implementation's error returns.
/// </summary>
[Serializable]
public class AicException : Exception
{
    public AicException(string message) : base(message) { }

    public AicException(string message, Exception inner) : base(message, inner) { }
}
