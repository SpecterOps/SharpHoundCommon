using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundRPC.NetAPINative;
using SharpHoundRPC.PortScanner;

namespace SharpHoundCommonLib;

/// <summary>
/// Resolves hostnames and IP addresses to Active Directory SIDs.
/// Extracted from LdapUtils to give host resolution a single, focused home.
/// </summary>
internal class HostResolver {
    private static readonly AdaptiveTimeout RequestNetBiosNameAdaptiveTimeout = new AdaptiveTimeout(
        maxTimeout: TimeSpan.FromMinutes(1),
        Logging.LogProvider.CreateLogger("HostResolver.RequestNETBIOSName"));

    private static readonly AdaptiveTimeout CallNetWkstaGetInfoAdaptiveTimeout = new AdaptiveTimeout(
        maxTimeout: TimeSpan.FromMinutes(2),
        Logging.LogProvider.CreateLogger("HostResolver.NetWkstaGetInfo"));

    private static readonly byte[] NameRequest = {
        0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
        0x00, 0x01
    };

    private readonly ConcurrentDictionary<string, string> _hostResolutionMap =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly PrincipalResolver _principalResolver;
    private readonly IPortScanner _portScanner;
    private readonly NativeMethods _nativeMethods;
    private readonly ILogger _log;

    internal HostResolver(PrincipalResolver principalResolver, IPortScanner portScanner,
        NativeMethods nativeMethods, ILogger log) {
        _principalResolver = principalResolver;
        _portScanner = portScanner;
        _nativeMethods = nativeMethods;
        _log = log;
    }

    internal async Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain) {
        var strippedHost = Helpers.StripServicePrincipalName(host).ToUpper().TrimEnd('$');
        if (string.IsNullOrEmpty(strippedHost)) {
            return (false, string.Empty);
        }

        if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return (sid != null, sid);

        // NetWkstaGetInfo is our most reliable indicator if successful
        if (await GetWorkstationInfo(strippedHost) is (true, var workstationInfo)) {
            var tempName = workstationInfo.ComputerName;
            var tempDomain = workstationInfo.LanGroup;
            _log.LogTrace("Get workstation info for {HostName} succeeded. Workstation {ComputerName} found.", host, tempName);

            if (string.IsNullOrWhiteSpace(tempDomain)) {
                tempDomain = domain;
            }

            if (!string.IsNullOrWhiteSpace(tempName)) {
                tempName = $"{tempName}$".ToUpper();
                if (await _principalResolver.ResolveAccountName(tempName, tempDomain) is (true, var principal)) {
                    _hostResolutionMap.TryAdd(strippedHost, principal.ObjectIdentifier);
                    return (true, principal.ObjectIdentifier);
                }
            }
        }

        // Try NETBIOS name via UDP socket
        try {
            var (requestNetBiosNameSuccess, netBiosName) =
                await RequestNETBIOSNameFromComputerWithTimeout(strippedHost, domain);
            if (requestNetBiosNameSuccess && !string.IsNullOrWhiteSpace(netBiosName)) {
                var result = await _principalResolver.ResolveAccountName($"{netBiosName}$", domain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }
            }
        }
        catch (TimeoutException) {
            _log.LogDebug("RequestNETBIOSNameFromComputer timeout on host {Host}, domain {Domain}.", strippedHost, domain);
        }

        // Handle non-IP hostnames
        if (!IPAddress.TryParse(strippedHost, out _)) {
            if (strippedHost.Contains(".")) {
                var split = strippedHost.Split('.');
                var name = split[0];
                var result = await _principalResolver.ResolveAccountName($"{name}$", domain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }

                var tempDomain = string.Join(".", split.Skip(1).ToArray());
                result = await _principalResolver.ResolveAccountName($"{name}$", tempDomain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }
            }
            else {
                var result = await _principalResolver.ResolveAccountName($"{strippedHost}$", domain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }
            }
        }

        try {
            // Blocking External Call
            var resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
            var split = resolvedHostname.Split('.');
            var name = split[0];
            var result = await _principalResolver.ResolveAccountName($"{name}$", domain);
            if (result.Success) {
                _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                return (true, result.Principal.ObjectIdentifier);
            }

            var tempDomain = string.Join(".", split.Skip(1).ToArray());
            result = await _principalResolver.ResolveAccountName($"{name}$", tempDomain);
            if (result.Success) {
                _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                return (true, result.Principal.ObjectIdentifier);
            }
        }
        catch {
            //pass
        }

        _hostResolutionMap.TryAdd(strippedHost, null);
        return (false, "");
    }

    private async Task<(bool Success, NetAPIStructs.WorkstationInfo100 Info)> GetWorkstationInfo(string hostname) {
        if (!await _portScanner.CheckPort(hostname)) {
            _log.LogTrace("CheckPort returned false for {HostName}.", hostname);
            return (false, default);
        }

        // Blocking External Call
        var result = await CallNetWkstaGetInfoAdaptiveTimeout.ExecuteNetAPIWithTimeout(
            (_) => _nativeMethods.CallNetWkstaGetInfo(hostname));

        if (result.IsSuccess)
            return (true, result.Value);

        _log.LogError(result.Error);
        return (false, default);
    }

    private static async Task<(bool Success, string NetBiosName)> RequestNETBIOSNameFromComputerWithTimeout(
        string server, string domain) {
        var result = await RequestNetBiosNameAdaptiveTimeout.ExecuteWithTimeout(
            async (timeoutToken) => await RequestNETBIOSNameFromComputerAsync(server, domain, timeoutToken));
        if (result.IsSuccess)
            return (result.Value.Success, result.Value.NetBiosName);

        throw new TimeoutException();
    }

    private static async Task<(bool Success, string NetBiosName)> RequestNETBIOSNameFromComputerAsync(
        string server, string domain, CancellationToken cancellationToken = default) {
        var receiveBuffer = new byte[1024];
        var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try {
            requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
            EndPoint remoteEndpoint;

            if (IPAddress.TryParse(server, out var parsedAddress)) {
                remoteEndpoint = new IPEndPoint(parsedAddress, 137);
            }
            else {
                try {
                    IPAddress address;
                    if (server.Contains("."))
                        address = (await Dns.GetHostAddressesAsync(server))
                            .First(x => x.AddressFamily == AddressFamily.InterNetwork);
                    else
                        address = (await Dns.GetHostAddressesAsync($"{server}.{domain}"))[0];

                    if (address == null) {
                        return (false, null);
                    }

                    remoteEndpoint = new IPEndPoint(address, 137);
                }
                catch {
                    return (false, null);
                }
            }

            var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
            cancellationToken.ThrowIfCancellationRequested();
            // Blocking External Call
            requestSocket.Bind(originEndpoint);

            try {
                // Blocking External Call
                requestSocket.SendTo(NameRequest, remoteEndpoint);
                cancellationToken.ThrowIfCancellationRequested();
                // Blocking External Call
                var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                if (receivedByteCount >= 90) {
                    var netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                    return (true, netbios);
                }

                return (false, null);
            }
            catch (SocketException) {
                return (false, null);
            }
        }
        finally {
            requestSocket.Close();
        }
    }
}
