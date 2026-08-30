using System;
using System.Text;

namespace Varwof.Aic.Tests;

/// <summary>Hex helpers mirroring encoding/hex in Go (port of TestHex).</summary>
public static class TestHex
{
    public static string EncodeHex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (byte x in b)
        {
            sb.Append(x.ToString("x2"));
        }
        return sb.ToString();
    }

    public static byte[] DecodeHex(string s)
    {
        s = s.Replace(" ", "").Replace("\n", "").Replace("\r", "").Replace("\t", "");
        if (s.Length % 2 != 0)
        {
            throw new FormatException("hex string has odd length");
        }
        byte[] outBytes = new byte[s.Length / 2];
        for (int i = 0; i < outBytes.Length; i++)
        {
            outBytes[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        }
        return outBytes;
    }
}
