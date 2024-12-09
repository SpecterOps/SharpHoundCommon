#nullable enable

using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;
using System;
using System.Collections.Specialized;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors
{
    public class SmbProcessor(int timeoutMs, ILogger? log = null)
    {
        private readonly ILogger _log = log ?? Logging.LogProvider.CreateLogger("SmbProcessor");
        int _timeoutMs = timeoutMs;

        public async Task<ApiResult<SmbInfo>> Scan(string host)
        {
            var scanner = new SmbScanner();
            var result = await scanner.Scan(host, 445, _timeoutMs);

            if (result.Success && result.Info != null)
            {
                var info = new SmbInfo()
                {
                    SigningEnabled = result.Info.SmbSigning,
                    OsVersion = result.Info.OsVersion,
                    OsBuild = result.Info.OsBuildNumber.ToString(),
                    DnsComputerName = result.Info.DnsComputerName,
                };

                return ApiResult<SmbInfo>.CreateSuccess(info);
            }
            else
            {
                return ApiResult<SmbInfo>.CreateError(result.ErrorMessage ?? "Unknown error");
            }
        }

    }


    public enum SmbVersion
    {
        Unknown,
        SMBv1,
        SMBv2
    }

    public class SmbScanResult
    {
        public SmbScanResult(string host)
        {
            Host = host;
        }

        public string Host { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public NTLMInfo? Info { get; set; }
        public SmbVersion SmbVersion { get; set; }
    }

    public class SMBPacket
    {
        public SMBPacket(bool signingEnabled)
        {
            if (signingEnabled)
            {
                SMB_Signing = signingEnabled;
                SMB_Session_Key_Length = [0x00, 0x00];
                SMB_Negotiate_Flags = [0x15, 0x82, 0x08, 0xa0];
            }
            else
            {
                SMB_Signing = signingEnabled;
                SMB_Session_Key_Length = [0x00, 0x00];
                SMB_Negotiate_Flags = [0x05, 0x80, 0x08, 0xa0];
            }
        }

        public OrderedDictionary? Packet_SMB_Header { get; set; }
        public OrderedDictionary? Packet_SMB2_Header { get; set; }
        public OrderedDictionary? Packet_SMB_Data { get; set; }
        public OrderedDictionary? Packet_SMB2_Data { get; set; }
        public OrderedDictionary? Packet_NTLMSSP_Negotiate { get; set; }
        public OrderedDictionary? Packet_NTLMSSP_Auth { get; set; }
        public OrderedDictionary? Packet_RPC_Data { get; set; }
        public OrderedDictionary? Packet_SCM_Data { get; set; }
        public bool SMB_Signing { get; set; }
        public byte[]? SMB_Session_ID { get; set; }
        public byte[] SMB_Session_Key_Length { get; set; }
        public byte[] SMB_Negotiate_Flags { get; set; }
        public byte[]? Session_Key { get; set; }
    }

    public class NTLMInfo
    {
        public string? NativeOs { get; set; }
        public string? NativeLanManager { get; set; }
        public string? NbtDomainName { get; set; }
        public string? NbtComputer { get; set; }
        public string? DomainName { get; set; }
        public short OsBuildNumber { get; set; }
        public string? OsVersion { get; set; }
        public string? DnsComputerName { get; set; }
        public string? DnsDomainName { get; set; }
        public string? DnsTreeName { get; set; }
        public DateTime TimeStamp { get; set; }
        public bool SmbSigning { get; set; }

        public static NTLMInfo FromBytes(byte[] buf)
        {
            NTLMInfo ntlminfo = new NTLMInfo();
            string NTLMSSP_Negotiate = BitConverter.ToString(buf).Replace("-", "");
            int off;
            off = NTLMSSP_Negotiate.IndexOf("4E544C4D53535000") / 2;
            int NTLMSSP_Negotiate_Len = (NTLMSSP_Negotiate.Length - NTLMSSP_Negotiate.IndexOf("4E544C4D53535000")) / 2;
            byte[] ntlm = new byte[NTLMSSP_Negotiate_Len];
            Array.Copy(buf, off, ntlm, 0, NTLMSSP_Negotiate_Len);

            NTLMSSP_Negotiate_Len = BitConverter.ToInt16(ntlm, 0xc);
            off = BitConverter.ToInt16(ntlm, 0x10);
            ntlminfo.OsBuildNumber = BitConverter.ToInt16(ntlm, off - 6);
            ntlminfo.OsVersion = $@"{ntlm[off - 8]}.{ntlm[off - 7]}";

            off += NTLMSSP_Negotiate_Len;
            int type = BitConverter.ToInt16(ntlm, off);

            while (type != 0)
            {
                off += 2;
                NTLMSSP_Negotiate_Len = BitConverter.ToInt16(ntlm, off);
                off += 2;
                switch (type)
                {
                    case 1:
                        ntlminfo.NbtComputer = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                        break;
                    case 2:
                        ntlminfo.NbtDomainName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                        break;
                    case 3:
                        ntlminfo.DnsComputerName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                        break;
                    case 4:
                        ntlminfo.DnsDomainName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                        break;
                    case 5:
                        ntlminfo.DnsTreeName = Encoding.Unicode.GetString(ntlm, off, NTLMSSP_Negotiate_Len);
                        break;
                    case 7:
                        ntlminfo.TimeStamp = DateTime.FromFileTime(BitConverter.ToInt64(ntlm, off));
                        break;
                }
                off += NTLMSSP_Negotiate_Len;
                type = BitConverter.ToInt16(ntlm, off);
            }

            return ntlminfo;
        }
    }
    
    public class SmbScanner
    { 
        public async Task<SmbScanResult> Scan(string host, int port, int timeoutMs = 10000)
        {
            var result = new SmbScanResult(host)
            {
                Success = false,
                SmbVersion = SmbVersion.Unknown
            };

            var SMBClientReceive = new byte[2048];
            TcpClient? SMB_Client = null;
            NetworkStream? SMB_Client_Stream = null;

            try
            {
                SMB_Client = await ConnectAsync(host, port, timeoutMs);

                if (!SMB_Client.Connected)
                {
                    result.ErrorMessage = "SMBInfo can't connect!";
                    return result;
                }

                SMB_Client_Stream = SMB_Client.GetStream();

                using var operationCts = new System.Threading.CancellationTokenSource(timeoutMs);

                if (port == 139)
                {
                    await SendStreamAsync(SMB_Client_Stream, GetNtbiosTCPData(), operationCts.Token);
                }

                try
                {
                    // Try SMBv1 first
                    SMBClientReceive = await SendStreamAsync(SMB_Client_Stream, GetNegotiateSMBv1Data(), operationCts.Token);

                    bool singingEnabled = BitConverter.ToString(SMBClientReceive).Replace("-", "").Substring(78, 2) == "0F";

                    SMBClientReceive = await SendStreamAsync(SMB_Client_Stream, GetNTLMSSPNegotiatev1Data(), operationCts.Token);

                    int len = BitConverter.ToInt16(SMBClientReceive, 43);
                    string[]? ss = null;

                    if (Encoding.Unicode.GetString(SMBClientReceive, len + 47, SMBClientReceive.Length - len - 47).Split('\0')[0].ToLower().Contains("windows"))
                    {
                        ss = Encoding.Unicode.GetString(SMBClientReceive, len + 47, SMBClientReceive.Length - len - 47).Split('\0');
                    }
                    else
                    {
                        ss = Encoding.Unicode.GetString(SMBClientReceive, len + 48, SMBClientReceive.Length - len - 48).Split('\0');
                    }

                    if (ss.Length >= 2)
                    {
                        result.Info = NTLMInfo.FromBytes(SMBClientReceive);
                        result.Info.NativeOs = ss[0];
                        result.Info.NativeLanManager = ss[1];
                        result.Info.SmbSigning = singingEnabled;
                    }

                    result.SmbVersion = SmbVersion.SMBv1;
                    result.Success = true;
                }
                catch
                {
                    // If SMBv1 fails, try SMBv2 with a new connection
                    if (SMB_Client != null)
                    {
                        SMB_Client.Close();
                    }

                    SMB_Client = await ConnectAsync(host, port, 10000);
                    SMB_Client_Stream = SMB_Client.GetStream();

                    SMBClientReceive = await SendStreamAsync(SMB_Client_Stream, GetNegotiateSMBv2Data1(), operationCts.Token);
                    if (BitConverter.ToString([SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7]]).ToLower() == "ff-53-4d-42")
                    {
                        result.ErrorMessage = "Could not connect with SMBv2";
                        return result;
                    }

                    bool signingEnabled = BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03";
                    var SMBPackets = new SMBPacket(signingEnabled);
                    
                    

                    await SendStreamAsync(SMB_Client_Stream, GetNegotiateSMBv2Data2(), operationCts.Token);
                    SMBClientReceive = await SendStreamAsync(SMB_Client_Stream, GetNTLMSSPNegotiatev2Data(SMBPackets), operationCts.Token);

                    result.Info = NTLMInfo.FromBytes(SMBClientReceive);
                    result.Info.SmbSigning = SMBPackets.SMB_Signing;

                    result.SmbVersion = SmbVersion.SMBv2;
                    result.Success = true;
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                SMB_Client?.Close();
            }

            return result;
        }

        private static async Task<TcpClient> ConnectAsync(string host, int port, int timeoutMs)
        {
            using var connectCts = new System.Threading.CancellationTokenSource(timeoutMs + 100);
            var client = new TcpClient();

            client.Client.SendTimeout = timeoutMs;
            client.Client.ReceiveTimeout = timeoutMs;

            try
            {
                var connectTask = client.ConnectAsync(host, port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeoutMs, connectCts.Token)) != connectTask)
                {
                    client.Close();
                    throw new TimeoutException($"Connection to {host}:{port} timed out after {timeoutMs}ms");
                }

                await connectTask;
                return client;
            }
            catch (Exception ex) when (ex is SocketException || ex is TimeoutException)
            {
                client.Close();
                throw new TimeoutException($"Connection to {host}:{port} timed out after {timeoutMs}ms", ex);
            }
            catch
            {
                client.Close();
                throw;
            }
        }

        private static async Task<byte[]> SendStreamAsync(NetworkStream stream, byte[] BytesToSend, System.Threading.CancellationToken cancellationToken)
        {
            byte[] BytesReceived = new byte[2048];
            await stream.WriteAsync(BytesToSend, 0, BytesToSend.Length, cancellationToken);
            await stream.FlushAsync(cancellationToken);
            await stream.ReadAsync(BytesReceived, 0, BytesReceived.Length, cancellationToken);
            return BytesReceived;
        }

        private static byte[] GetNtbiosTCPData()
        {
            byte[] NtbiosTCPData = {
                0x81,0x00,0x00,0x44,0x20,0x43,0x4b,0x46,0x44,0x45,0x4e,0x45,0x43,0x46,0x44,0x45
                ,0x46,0x46,0x43,0x46,0x47,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43
                ,0x41,0x43,0x41,0x43,0x41,0x00,0x20,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
                ,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
                ,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
            };
            return NtbiosTCPData;
        }

        private static byte[] GetNegotiateSMBv1Data()
        {
            byte[] NegotiateSMBv1Data = {
                0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
                0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
                0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
                0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
                0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
                0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
                0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
            };
            return NegotiateSMBv1Data;
        }

        private static byte[] GetNTLMSSPNegotiatev1Data()
        {
            byte[] NTLMSSPNegotiatev1Data = {
                0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
                0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
                0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
                0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
                0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
                0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
                0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
                0x76, 0x00,0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
                0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00,
                0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00,
                0x50, 0x00, 0x61, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00,
                0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00, 0x20, 0x00,
                0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            return NTLMSSPNegotiatev1Data;
        }

        private static byte[] GetNegotiateSMBv2Data1()
        {
            byte[] NegotiateSMBData = {
                0x00, 0x00, 0x00, 0x45, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
                0x00, 0x00, 0x00, 0x18, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                0xAC, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02,
                0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32,
                0x00, 0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30, 0x30,
                0x32, 0x00, 0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x3F,
                0x3F, 0x3F, 0x00
            };
            return NegotiateSMBData;
        }

        private static byte[] GetNegotiateSMBv2Data2()
        {
            byte[] NegotiateSMB2Data = {
                0x00, 0x00, 0x00, 0x68, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
                0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02
            };
            return NegotiateSMB2Data;
        }

        private static byte[] GetNTLMSSPNegotiatev2Data(SMBPacket SMBPackets)
        {
            byte[] NTLMSSPNegotiateData = {
                0x00, 0x00, 0x00, 0x9A, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x58, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x60, 0x40, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
                0x05, 0x02, 0xA0, 0x36, 0x30, 0x34, 0xA0, 0x0E, 0x30, 0x0C,
                0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
                0x02, 0x0A, 0xA2, 0x22, 0x04, 0x20, 0x4E, 0x54, 0x4C, 0x4D,
                0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
                SMBPackets.SMB_Negotiate_Flags[0], SMBPackets.SMB_Negotiate_Flags[1],
                SMBPackets.SMB_Negotiate_Flags[2], SMBPackets.SMB_Negotiate_Flags[3],
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            return NTLMSSPNegotiateData;
        }
    }
}

#nullable disable