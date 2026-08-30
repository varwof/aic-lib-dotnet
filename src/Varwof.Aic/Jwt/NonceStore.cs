using System;
using System.Collections.Concurrent;
using System.Threading;
using Varwof.Aic;

namespace Varwof.Aic.Jwt;

/// <summary>
/// Nonce store for DA nonce / jti replay prevention. Mirrors Go
/// types/aicjwt/nonce.go. In-memory for reference deployments; production
/// should use a persistent store.
/// </summary>
public static class NonceStore
{
    public interface IStore
    {
        /// <summary>Records the nonce, rejecting duplicates.</summary>
        void CheckAndAdd(string nonce);
    }

    /// <summary>Replayed DA nonce.</summary>
    public sealed class NonceReuseException : AicException
    {
        public string Nonce { get; }

        public NonceReuseException(string nonce) : base("nonce reuse: " + nonce)
        {
            Nonce = nonce;
        }
    }

    /// <summary>
    /// In-memory store with TTL and a size cap so it cannot grow unbounded.
    /// </summary>
    public sealed class MemNonceStore : IStore
    {
        private readonly ConcurrentDictionary<string, long> _seen = new();
        private readonly long _ttlTicks;
        private readonly int _maxEntries;
        private long _inserts;

        /// <summary>Default TTL (1 day, matching the max token lifetime) and entry cap.</summary>
        public MemNonceStore() : this(TimeSpan.FromDays(1), 1_000_000) { }

        public MemNonceStore(TimeSpan ttl, int maxEntries)
        {
            _ttlTicks = ttl > TimeSpan.Zero ? ttl.Ticks : TimeSpan.FromDays(1).Ticks;
            _maxEntries = maxEntries > 0 ? maxEntries : 1_000_000;
        }

        public void CheckAndAdd(string nonce)
        {
            long now = DateTime.UtcNow.Ticks;
            if (_seen.TryGetValue(nonce, out long existing) && existing > now)
            {
                throw new NonceReuseException(nonce);
            }
            _seen[nonce] = now + _ttlTicks;
            if (Interlocked.Increment(ref _inserts) % 256 == 0)
            {
                SweepExpired(DateTime.UtcNow.Ticks);
            }
            else if (_seen.Count > _maxEntries)
            {
                SweepExpired(DateTime.UtcNow.Ticks);
            }
        }

        private void SweepExpired(long now)
        {
            foreach (KeyValuePair<string, long> kv in _seen)
            {
                if (kv.Value <= now)
                {
                    _seen.TryRemove(kv.Key, out _);
                }
            }
        }
    }

    public static IStore NewMemNonceStore() => new MemNonceStore();
}