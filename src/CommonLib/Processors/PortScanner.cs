using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundRPC.PortScanner;

namespace SharpHoundCommonLib.Processors {
    /// <summary>
    ///     Owns state shared by PortScanner instances and gives that state an explicit lifetime.
    /// </summary>
    public sealed class PortScannerContext : IDisposable {
        private readonly PortScanner.ScanCache _scanCache = new();
        private int _disposed;

        /// <summary>
        ///     Creates a <see cref="PortScanner"/> that shares its scan cache with other scanners
        ///     created by this context.
        /// </summary>
        public PortScanner CreatePortScanner(ILogger log = null, int maxTimeout = 10000) {
            if (Volatile.Read(ref _disposed) != 0) {
                throw new ObjectDisposedException(nameof(PortScannerContext));
            }

            return new PortScanner(_scanCache, log, maxTimeout);
        }

        /// <summary>
        ///     Clears the shared scanner state. Scanners created by this context must not
        ///     be used after the context is disposed.
        /// </summary>
        public void Dispose() {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) {
                return;
            }

            _scanCache.Dispose();
        }
    }

    public class PortScanner : IPortScanner {
        private readonly ILogger _log;
        private readonly AdaptiveTimeout _adaptiveTimeout;
        private readonly ScanCache _scanCache;

        internal sealed class ScanCache : IDisposable {
            private readonly ConcurrentDictionary<PingCacheKey, bool> _portScanCache = new();
            private int _disposed;

            public bool TryGet(PingCacheKey key, out bool status) {
                ThrowIfDisposed();
                return _portScanCache.TryGetValue(key, out status);
            }

            public void Add(PingCacheKey key, bool status) {
                ThrowIfDisposed();
                _portScanCache.TryAdd(key, status);
            }

            public void Dispose() {
                if (Interlocked.Exchange(ref _disposed, 1) != 0) {
                    return;
                }

                _portScanCache.Clear();
            }

            private void ThrowIfDisposed() {
                if (Volatile.Read(ref _disposed) != 0) {
                    throw new ObjectDisposedException(nameof(PortScannerContext));
                }
            }
        }

        public PortScanner() : this((ILogger)null) {
            
        }

        public PortScanner(ILogger log = null, int maxTimeout = 10000) : this(
            new ScanCache(), log, maxTimeout) {
        }

        internal PortScanner(ScanCache scanCache, ILogger log = null, int maxTimeout = 10000) {
            _scanCache = scanCache;
            _log = log ?? Logging.LogProvider.CreateLogger("PortScanner");
            _adaptiveTimeout = new AdaptiveTimeout(TimeSpan.FromMilliseconds(maxTimeout), _log);
        }

        /// <summary>
        ///     Checks if a specified port is open on a host. Defaults to 445 (SMB)
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <param name="throwError">Used as a switch to control if this method should throw exceptions that  occur.</param>
        /// <returns>True if port is open, otherwise false</returns>
        public virtual async Task<bool> CheckPort(string hostname, int port = 445,
            bool throwError = false) {
            var key = new PingCacheKey {
                Port = port,
                HostName = hostname
            };

            if (_scanCache.TryGet(key, out var status)) {
                _log.LogTrace("Port scan cache hit for {HostName}:{Port}: {Status}", hostname, port, status);
                return status;
            }

            try {
                using var client = new TcpClient();
                var ca = await _adaptiveTimeout.ExecuteWithTimeout((_) => client.ConnectAsync(hostname, port));
                if (!ca.IsSuccess) {
                    _log.LogDebug("{HostName} did not respond to scan on port {Port} within {TimeoutMs}ms", hostname, port, _adaptiveTimeout.GetAdaptiveTimeout().TotalMilliseconds);
                    if (throwError) {
                        throw new TimeoutException(ca.Error);
                    }
                    _scanCache.Add(key, false);
                    return false;
                }

                _log.LogTrace("CheckPort Succeeded for {HostName}:{Port}", hostname, port);
                _scanCache.Add(key, true);
                return true;
            }
            catch (Exception e) {
                // task threw exception
                _log.LogDebug(e, "Exception checking {Hostname}:{Port}", hostname, port);
                if (throwError) {
                    throw;
                }

                _scanCache.Add(key, false);
                return false;
            }
        }

        internal class PingCacheKey {
            internal string HostName { get; set; }
            internal int Port { get; set; }

            protected bool Equals(PingCacheKey other) {
                return HostName == other.HostName && Port == other.Port;
            }

            public override bool Equals(object obj) {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != GetType()) return false;
                return Equals((PingCacheKey)obj);
            }

            public override int GetHashCode() {
                unchecked {
                    return (HostName.GetHashCode() * 397) ^ Port;
                }
            }
        }
    }
}
