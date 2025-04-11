using SharpHoundCommonLib.Processors;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundCommonLib.SMB.SMB1;
using SharpHoundCommonLib.SMB.SMB2;
using SharpHoundCommonLib.SMB.NetBIOS;
using System.CodeDom;
using Microsoft.Extensions.Logging;
using SharpHoundRPC;
using SharpHoundRPC.Registry;
using Microsoft.Win32;

namespace SharpHoundCommonLib.SMB
{
    // Define an interface
    public interface ISmbScanner
    {
        public Task<SharpHoundRPC.Result<SmbScanInfo>> ScanHost(string host, int port = 445);
    }

    /// <summary>
    /// Scans the SMB configuration of a server by constructing raw SMB packets
    /// and analyzing data returned by the server. Will attempt to use both
    /// SMB1 and SMB2 packets supporting all SMB dialects (SMB1-3.x). This is
    /// used for checking if SMB signing is required.
    /// </summary>
    public class SmbScanner: ISmbScanner
    {
        /// <summary>
        /// Timeout value used when connecting to hosts or waiting for a response.
        /// </summary>
        public int TimeoutMs { get; set; } = 2000;

        public ILogger _log;

        public SmbScanner(ILogger log)
        {
            _log = log ?? Logging.LogProvider.CreateLogger("SmbScanner"); ;
        }


        /// <summary>
        /// Scans SMB on the remote server by sending an SMB negotiate message
        /// and analyzing the response. It will attempt to elicit a response using 
        /// an SMB1 message and then SMB2 (if SMB1 fails).
        /// </summary>
        /// <param name="host">The hostname or IP address to check</param>
        /// <param name="port">The port to connect to (default SMB port is 445)</param>
        /// <returns>Result object containing SMB signing information</returns>
        public async Task<SharpHoundRPC.Result<SmbScanInfo>> ScanHost(string host, int port = 445)
        {

            var isLocalMachine = NativeUtils.IsCurrentMachineFqdn(host);
            if (isLocalMachine)
            {
                // When accessing the SMB directly port from localhost, it'll disconnect. 
                // Side step that by just collecting the data from the registry.
                return CheckRegistrySigningRequired(host);
            }



            // Try SMB1 negotiate first as it'll elicit an SMB1 or SMB2 response (if either is enabled)
            var smb1result = await TrySMBNegotiate(host, port, true);

            if (smb1result.IsSuccess)
                return smb1result;

            // SMB1 failed, so try an SMB2 negotiate in case SMB1 is disabled or the SMB3 dialect is required
            return await TrySMBNegotiate(host, port, false);
        }

        /// <summary>
        /// Determines if SMB signing is required using registry values.
        /// </summary>
        private SharpHoundRPC.Result<SmbScanInfo> CheckRegistrySigningRequired(string host)
        {
            const string keyPath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
            const string requireValueName = "RequireSecuritySignature";
            const string enableValueName = "EnableSecuritySignature";

            try
            {
                var requireRegistryValue = Registry.GetValue($@"HKEY_LOCAL_MACHINE\{keyPath}", requireValueName, null);
                var enableRegistryValue = Registry.GetValue($@"HKEY_LOCAL_MACHINE\{keyPath}", enableValueName, null);

                bool signingRequired = false;
                bool signingEnabled = false;

                if (requireRegistryValue != null)
                {
                    signingRequired = Convert.ToInt32(requireRegistryValue) != 0;
                }

                if (enableRegistryValue != null)
                {
                    signingEnabled = Convert.ToInt32(enableRegistryValue) != 0;
                }

                return SharpHoundRPC.Result<SmbScanInfo>.Ok(new SmbScanInfo(host)
                {
                    SigningRequired = signingEnabled && signingRequired
                });
            }
            catch (Exception ex)
            {
                return SharpHoundRPC.Result<SmbScanInfo>.Fail($"Registry check failed: {ex.Message}");
            }
        }


        /// <summary>
        /// Sends either an SMB1 or SMB2 negoitate message to check if SMB signing is required.
        /// </summary>
        private async Task<SharpHoundRPC.Result<SmbScanInfo>> TrySMBNegotiate(string host, int port, bool useSMB1 = false)
        {
            try
            {
                byte[] negoReqBytes;
                if (useSMB1)
                {
                    var negotiateRequest = new SMB1NegotiateRequest();
                    negoReqBytes = negotiateRequest.ToBytes();
                }
                else
                {
                    var negotiateRequest = new SMB2NegotiateRequest(host);
                    negoReqBytes = negotiateRequest.ToBytes();
                }

                var negoRespBytes = await SendAndReceiveData(host, port, TimeoutMs, negoReqBytes);


                var scanInfo = new SmbScanInfo(host)
                {
                    SigningRequired = CheckResponseRequiresSigning(negoRespBytes, useSMB1)
                };

                return SharpHoundRPC.Result<SmbScanInfo>.Ok(scanInfo);
            }
            catch (OperationCanceledException)
            {
                return SharpHoundRPC.Result<SmbScanInfo>.Fail("Timed out");
            }
            catch (Exception ex)
            {
                string protocol = useSMB1 ? "SMB1" : "SMB2";
                return SharpHoundRPC.Result<SmbScanInfo>.Fail($"{protocol} negotiate failed. {ex.Message}");
            }
        }


        /// <summary>
        /// Parses an SMB response, determines SMB response type(SMB1/SMB2), 
        /// and parses the appropriate SMB1/SMB2 negotiate response message to 
        /// see if SMB signing is required.
        /// </summary>
        internal bool CheckResponseRequiresSigning(byte[] responsePacket, bool parseSMB1Response)
        {
            if (responsePacket == null)
                throw new ArgumentNullException(nameof(responsePacket));

            // 1) Read the NetBIOS Header
            var netbiosHeader = NetBIOSHeader.FromBytes(responsePacket);

            if (netbiosHeader.Type != NetBIOSSessionType.SessionMessage)
                throw new InvalidOperationException("Expected NetBIOS session message");

            // Sanity check the length and 
            // 4 = Size of NetBIOS header
            if (!(netbiosHeader.Length > 0 && netbiosHeader.Length <= responsePacket.Length - 4))
                throw new FormatException($"Invalid NetBIOS message length: {netbiosHeader.Length}");

            // 2) Read the SMB Header
            var protocol = BitConverter.ToUInt32([
                responsePacket[4],
                responsePacket[5],
                responsePacket[6],
                responsePacket[7]
            ], 0);

            bool error;
            bool signingRequired;


            // Parse the response:

            // Note:
            // - 99% of the time Windows will return an SMB2 response. Legacy systems or odd devices may return an SMB1
            // - If you send an SMB negotiate request packet, most Windows versions will respond with an SMB2 response.
            //   due to the SMB negotiate request's dialect stating SMB2 is supported.

            // Parse SMB2 negotiate response packet
            if (protocol == SMB2Header.SpecificationProtocolId)
            {
                (error, signingRequired) = CheckSMB2SigningRequired(responsePacket);

                if (error)
                    throw new FormatException($"Failed to parse SMB2 response: {Convert.ToBase64String(responsePacket)}");
                else
                    return signingRequired;
            }

            // Parse SMB1 negotiate response packet
            if (protocol == SMB1Header.SpecificationProtocolId && parseSMB1Response)
            {
                (error, signingRequired) = CheckSMB1SigningRequired(responsePacket);

                if (error)
                    throw new FormatException($"Failed to parse SMB1 response: {Convert.ToBase64String(responsePacket)}");
                else
                    return signingRequired;
            }

            throw new FormatException($"Invalid SMB protocol identifier: 0x{protocol:X8}");
        }


        /// <summary>
        /// Parses an SMB2 negotiate response to determine if SMB signing is required.
        /// </summary>
        /// <remarks>
        /// The minimal validation of the SMB2 response packet is done, and parsing
        /// only occurs until the SecurityMode field occurs. The entire SMB2 negotiate
        /// response is not parsed/validated.
        /// 
        /// For more information, see:
        /// <para>
        /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5">MS-SMB2 2.2.4 SMB2 NEGOTIATE Response</see>
        /// </para>
        /// <para>
        /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4">MS-SMB2 2.2.1.2 SMB2 Packet Header - SYNC</see>
        /// </para>
        /// </remarks>
        internal (bool error, bool signingRequired) CheckSMB2SigningRequired(byte[] responsePacket)
        {
            using var memoryStream = new MemoryStream(responsePacket, 4, responsePacket.Length - 4); // Skip the NetBIOS header
            using var reader = new BinaryReader(memoryStream);

            var header = SMB2Header.FromBytes(reader);

            if (header.Command != SMB2Constants.NegotiateCommand)
            {
                _log.LogDebug($"Expected SMB2 Negotiate command (0x0), got 0x{header.Command:X2}. Packet: {Convert.ToBase64String(responsePacket)}");
                return (true, false);
            }

            if (header.StatusOrChannelSequence != SMB2Constants.StatusSuccess)
            {
                _log.LogDebug($"Expected successful SMB2 header status, got 0x{header.StatusOrChannelSequence:X4}. Packet: {Convert.ToBase64String(responsePacket)}");
                return (true, false);
            }

            // Validate structure size of negotiate response
            var negotiateStructureSize = reader.ReadUInt16();
            

            // Read security mode, which contains signing information
            var securityMode = reader.ReadUInt16();

            // Check if signing is required (bit 1)
            bool signingEnabled = (securityMode & SMB2Constants.SigningEnabled) != 0;
            bool signingRequired = (securityMode & SMB2Constants.SigningRequired) != 0;

            if (!signingEnabled)
                return (false, false);

            return (false, signingRequired);
        }

        /// <summary>
        /// Parses an SMB1 negotiate response to determine if SMB signing is required.
        /// </summary>
        /// <remarks>
        /// The minimal validation of the SMB1 response packet is done, and parsing
        /// only occurs until the SecurityMode field occurs. The entire SMB1 negotiate
        /// response is not parsed/validated.
        /// 
        /// For more information, see:
        /// <para>
        /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a4229e1a-8a4e-489a-a2eb-11b7f360e60c">MS-CIFS 2.2.4.52.2 Negotiate Response</see>
        /// </para>
        /// </remarks>
        internal (bool error, bool signingRequired) CheckSMB1SigningRequired(byte[] responsePacket)
        {
            try
            {
                using var memoryStream = new MemoryStream(responsePacket, 4, responsePacket.Length - 4); // Skip the NetBIOS header
                using var reader = new BinaryReader(memoryStream);

                var header = SMB1Header.FromBytes(reader);

                // Verify it's a negotiate request (command = 0x72)
                if (header.Command != SMB1Command.Negotiate)
                {
                    _log.LogDebug($"Expected SMB_COM_NEGOTIATE (0x72), got 0x{header.Command:X2}. Packet: {Convert.ToBase64String(responsePacket)}");
                    return (true, true);
                }

                if (!header.Flags.HasFlag(SMB1Flags.Reply))
                {
                    _log.LogDebug($"Expected response flag in SMB1 negotiate response. Packet: {Convert.ToBase64String(responsePacket)}");
                    return (true, true);
                }


                // Parse the relevant parts of the Negotiate Response
                // See MS-CIFS 2.2.4.52.2 Response
                var wordCount = reader.ReadByte();
                ushort dialectIndex = reader.ReadUInt16();

                // For SMB_COM_NEGOTIATE, WordCount should be 0
                if (wordCount < 1)
                    throw new FormatException($"Expected WordCount >0, got {wordCount}. Packet: {Convert.ToBase64String(responsePacket)}");

                // If the server does not support any of the listed dialects, it MUST return a DialectIndex of 0XFFFF
                if (dialectIndex == 0xFFFF)
                    throw new FormatException($"No supported SMB1 dialect. Packet: {Convert.ToBase64String(responsePacket)}");

                byte securityMode = reader.ReadByte();


                bool signingEnabled = (securityMode & 0x04) != 0;
                bool signingRequired = (securityMode & 0x08) != 0;

                if (!signingEnabled)
                    return (false, false);

                return (false, signingRequired);

            }
            catch (Exception e)
            {
                _log.LogDebug($"Unhandled error parsing SMB1 nego response. Error: {e}.  Packet: {Convert.ToBase64String(responsePacket)}");
                return (true, true);
            }
        }

        /// <summary>
        /// Connects to a remote port on host with a timeout and
        /// sends data to the port and returns all bytes returned.
        /// </summary>
        private async Task<byte[]> SendAndReceiveData(string host, int port, int timeoutMs, byte[] data)
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(timeoutMs);

            await ConnectWithTimeoutAsync(client, host, port, cts.Token);
            
            using var stream = client.GetStream();
            await stream.WriteAsync(data, 0, data.Length, cts.Token);

            // Read the response
            byte[] responseBuffer = new byte[4096];
            int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length, cts.Token);

            var responseBytes = new byte[bytesRead];
            Array.Copy(responseBuffer, responseBytes, bytesRead);

            return responseBytes;
        }


        /// <summary>
        /// Connects to a remote host with a timeout.
        /// </summary>
        private async Task ConnectWithTimeoutAsync(TcpClient client, string host, int port, CancellationToken cancellationToken)
        {
            var connectTask = client.ConnectAsync(host, port);
            var timeoutTask = Task.Delay(-1, cancellationToken);

            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                // The timeout task completed first, so the connect task timed out
                throw new OperationCanceledException("Connection attempt timed out", cancellationToken);
            }

            // Check if the connect task faulted
            // This will throw any exception that occurred during the connect task
            await connectTask; 
        }
    }
}
