using System;
using System.Net;
using System.Net.Sockets;

namespace Varwof.Aic;

/// <summary>
/// Minimal CIDR prefix matcher (IPv4/IPv6) used by the allowed-cidr
/// constraint. Mirrors Go net/netip.Prefix.Contains.
/// </summary>
public sealed class Cidr
{
    private readonly byte[] _network;
    private readonly int _prefixBits;
    private readonly int _addrBytes;

    private Cidr(byte[] network, int prefixBits, int addrBytes)
    {
        _network = network;
        _prefixBits = prefixBits;
        _addrBytes = addrBytes;
    }

    public static Cidr Parse(string cidr)
    {
        try
        {
            int slash = cidr.LastIndexOf('/');
            if (slash < 0)
            {
                throw new AicException("missing prefix length");
            }
            string addr = cidr.Substring(0, slash);
            int bits = int.Parse(cidr.Substring(slash + 1));
            IPAddress ip = IPAddress.Parse(addr);
            byte[] raw = ip.GetAddressBytes();
            int maxBits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : -1;
            if (maxBits < 0)
            {
                throw new AicException("unsupported address family");
            }
            if (bits < 0 || bits > maxBits)
            {
                throw new AicException("prefix length out of range");
            }
            byte[] network = (byte[])raw.Clone();
            int fullBytes = bits / 8;
            int rem = bits % 8;
            if (fullBytes < network.Length)
            {
                for (int i = fullBytes + 1; i < network.Length; i++)
                {
                    network[i] = 0;
                }
                if (rem > 0)
                {
                    network[fullBytes] &= (byte)(0xff << (8 - rem));
                }
                else
                {
                    network[fullBytes] = 0;
                }
            }
            return new Cidr(network, bits, raw.Length);
        }
        catch (AicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AicException("invalid CIDR \"" + cidr + "\": " + ex.Message);
        }
    }

    public bool Contains(IPAddress ip)
    {
        byte[] raw = ip.GetAddressBytes();
        if (raw.Length != _addrBytes)
        {
            return false;
        }
        int fullBytes = _prefixBits / 8;
        for (int i = 0; i < fullBytes; i++)
        {
            if (raw[i] != _network[i])
            {
                return false;
            }
        }
        int rem = _prefixBits % 8;
        if (rem > 0)
        {
            int mask = 0xff << (8 - rem);
            if ((raw[fullBytes] & mask) != (_network[fullBytes] & mask))
            {
                return false;
            }
        }
        return true;
    }

    public override string ToString()
    {
        try
        {
            return new IPAddress(_network).ToString() + "/" + _prefixBits;
        }
        catch
        {
            return "<cidr>";
        }
    }
}