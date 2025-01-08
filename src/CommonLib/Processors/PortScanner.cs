using Microsoft.Extensions.Logging;
using SharpHoundRPC.PortScanner;
using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors;

public class PortScanner : IPortScanner
{
    private readonly ConcurrentDictionary<PortScanCacheKey, bool> PortScanCache = new();
    private readonly ILogger _log;
    public int Timeout { get; set; } = 10000;

    public PortScanner()
    {
        _log = Logging.LogProvider.CreateLogger("PortScanner");
    }

    public PortScanner(ILogger log = null)
    {
        _log = log ?? Logging.LogProvider.CreateLogger("PortScanner");
    }

    /// <summary>
    ///     Checks if a specified port is open on a host. Defaults to 445 (SMB)
    /// </summary>
    /// <param name="hostname"></param>
    /// <param name="port"></param>
    /// <param name="timeout">Timeout in milliseconds</param>
    /// <returns>True if port is open, otherwise false</returns>
    public virtual async Task<bool> CheckPort(string hostname, int port, bool throwError = false)
    {
        var key = new PortScanCacheKey
        {
            Port = port,
            HostName = hostname
        };

        if (PortScanCache.TryGetValue(key, out var status))
        {
            _log.LogTrace("Port scan cache hit for {HostName}:{Port}: {Status}", hostname, port, status);
            return status;
        }

        try
        {
            using var client = new TcpClient();
            var ca = client.ConnectAsync(hostname, port);
            if (await Task.WhenAny(ca, Task.Delay(Timeout)) == ca)
            {
                if (ca.IsFaulted)
                {
                    _log.LogDebug("PortScan faulted on {Hostname}:{Port} with error {Error}", hostname, port, ca.Exception);
                    PortScanCache.TryAdd(key, false);
                    return false;
                }
                PortScanCache.TryAdd(key, true);
                return true;
            }

            _log.LogDebug("{HostName} did not respond to scan on port {Port} within {Timeout}ms", hostname, port, Timeout);
            PortScanCache.TryAdd(key, false);

            if (throwError)
                throw new TimeoutException("Timed out");

            return false;
        }
        catch (Exception e)
        {
            _log.LogDebug(e, "Exception checking {Hostname}:{Port}", hostname, port);
            PortScanCache.TryAdd(key, false);

            if (throwError)
                throw;
            return false;
        }
    }

    public void ClearCache()
    {
        PortScanCache.Clear();
    }

    private class PortScanCacheKey
    {
        internal string HostName { get; set; }
        internal int Port { get; set; }

        protected bool Equals(PortScanCacheKey other)
        {
            return HostName == other.HostName && Port == other.Port;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((PortScanCacheKey)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (HostName.GetHashCode() * 397) ^ Port;
            }
        }
    }
}
