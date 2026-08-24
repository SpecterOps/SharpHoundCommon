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

namespace SharpHoundCommonLib {
    public partial class LdapUtils {
        private static readonly AdaptiveTimeout _requestNetBiosNameAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(1), Logging.LogProvider.CreateLogger(nameof(RequestNETBIOSNameFromComputerAsync)));

        private static readonly AdaptiveTimeout _callNetWkstaGetInfoAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger(nameof(NativeMethods.CallNetWkstaGetInfo)));

        private readonly ConcurrentDictionary<string, string>
            _hostResolutionMap = new(StringComparer.OrdinalIgnoreCase);
        private readonly IPortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;
        private static readonly byte[] NameRequest = {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };

        public async Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain) {
            //Remove SPN prefixes from the host name so we're working with a clean name
            var strippedHost = Helpers.StripServicePrincipalName(host).ToUpper().TrimEnd('$');
            if (string.IsNullOrEmpty(strippedHost)) {
                return (false, string.Empty);
            }

            if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return (sid != null, sid);

            //Immediately start with NetWkstaGetInfo as it's our most reliable indicator if successful
            if (await GetWorkstationInfo(strippedHost) is (true, var workstationInfo)) {
                var tempName = workstationInfo.ComputerName;
                var tempDomain = workstationInfo.LanGroup;
                _log.LogTrace("Get workstation info for {HostName} succeeded. Workstation {ComputerName} found.", host, tempName);

                if (string.IsNullOrWhiteSpace(tempDomain)) {
                    tempDomain = domain;
                }

                if (!string.IsNullOrWhiteSpace(tempName)) {
                    tempName = $"{tempName}$".ToUpper();
                    if (await ResolveAccountName(tempName, tempDomain) is (true, var principal)) {
                        _hostResolutionMap.TryAdd(strippedHost, principal.ObjectIdentifier);
                        return (true, principal.ObjectIdentifier);
                    }
                }
            }

            //Try some socket magic to get the NETBIOS name
            try {
                var (requestNetBiosNameSuccess, netBiosName) = await RequestNETBIOSNameFromComputerWithTimeout(strippedHost, domain);
                if (requestNetBiosNameSuccess) {
                    if (!string.IsNullOrWhiteSpace(netBiosName)) {
                        var result = await ResolveAccountName($"{netBiosName}$", domain);
                        if (result.Success) {
                            _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                            return (true, result.Principal.ObjectIdentifier);
                        }
                    }
                }
            } catch (TimeoutException) {
                _log.LogDebug("RequestNETBIOSNameFromComputer timeout on host {Host}, domain {Domain}.", strippedHost, domain);
            }

            //Start by handling non-IP address names
            if (!IPAddress.TryParse(strippedHost, out _)) {
                //PRIMARY.TESTLAB.LOCAL
                if (strippedHost.Contains(".")) {
                    var split = strippedHost.Split('.');
                    var name = split[0];
                    var result = await ResolveAccountName($"{name}$", domain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }

                    var tempDomain = string.Join(".", split.Skip(1).ToArray());
                    result = await ResolveAccountName($"{name}$", tempDomain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
                else {
                    //Format: WIN10 (probably a netbios name)
                    var result = await ResolveAccountName($"{strippedHost}$", domain);
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
                var result = await ResolveAccountName($"{name}$", domain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }

                var tempDomain = string.Join(".", split.Skip(1).ToArray());
                result = await ResolveAccountName($"{name}$", tempDomain);
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

        /// <summary>
        ///     Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private async Task<(bool Success, NetAPIStructs.WorkstationInfo100 Info)> GetWorkstationInfo(string hostname) {
            if (!await _portScanner.CheckPort(hostname)) {
                _log.LogTrace("CheckPort returned false for {HostName}.", hostname);
                return (false, default);
            }
            
            // Blocking External Call
            var result = await _callNetWkstaGetInfoAdaptiveTimeout.ExecuteNetAPIWithTimeout((_) => _nativeMethods.CallNetWkstaGetInfo(hostname));

            if (result.IsSuccess)
                return (true, result.Value);
            else
                _log.LogError(result.Error);

            return (false, default);
        }

        private static async Task<(bool Success, string NetBiosName)> RequestNETBIOSNameFromComputerWithTimeout(string server, string domain) {
            var result = await _requestNetBiosNameAdaptiveTimeout.ExecuteWithTimeout(async (timeoutToken) => await RequestNETBIOSNameFromComputerAsync(server, domain, timeoutToken));
            if (result.IsSuccess)
                return (result.Value.Success, result.Value.NetBiosName);
            else
                throw new TimeoutException();
        }

        /// <summary>
        ///     Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static async Task<(bool Success, string NetBiosName)> RequestNETBIOSNameFromComputerAsync(string server, string domain, CancellationToken cancellationToken = default) {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress))
                    remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                    //If its not an IP, we're going to try and resolve it from DNS
                    try {
                        IPAddress address;
                        if (server.Contains("."))
                            address = (await Dns
                                .GetHostAddressesAsync(server)).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        else
                            address = (await Dns.GetHostAddressesAsync($"{server}.{domain}"))[0];

                        if (address == null) {
                            return (false, null);
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch {
                        //Failed to resolve an IP, so return null
                        return (false, null);
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
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        /// Created for testing purposes
        /// </summary>
        /// <returns></returns>
    }
}
