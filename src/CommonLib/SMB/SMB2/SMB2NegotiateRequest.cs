using SharpHoundCommonLib.SMB.NetBIOS;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// Represents an SMB2 NEGOTIATE request
    /// Used to initiate an SMB connection and determine which dialect to use.
    /// Default values represent what is sent by default on a Windows 11 machine.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5">MS-SMB2 2.2.3 SMB2 NEGOTIATE Request</see>
    /// </para>
    /// </remarks>
    public class SMB2NegotiateRequest
    {
        // Properties for the negotiate request
        public ushort StructureSize { get; set; } = SMB2Constants.NegotiateRequestSize;
        public ushort SecurityMode { get; set; } = SMB2Constants.SigningRequired;
        public ushort Reserved { get; set; } = 0;
        public uint Capabilities { get; set; } = 0x000000FF; // All capabilities
        public Guid ClientGuid { get; set; } = Guid.NewGuid();
        public List<SMB2Dialect> Dialects { get; set; }
        public INegotiateContext[] NegotiateContexts { get; set; }

        public SMB2NegotiateRequest(string host)
        {
            // Default dialects
            Dialects =
            [
                SMB2Dialect.Smb202,
                SMB2Dialect.Smb21,
                SMB2Dialect.Smb30,
                SMB2Dialect.Smb302,
                SMB2Dialect.Smb311
            ];

            // Default contexts
            NegotiateContexts =
            [
                new SMB2PreauthIntegrityCapabilities(),
                new SMB2EncryptionCapabilities(),
                new SMB2CompressionCapabilities(),
                new SMB2SigningCapabilities(),
                new SMB2NetnameNegotiateContext(host),
                new SMB2RdmaTransformCapabilities()
            ];
        }

        /// <summary>
        /// Converts the negotiate request to a byte array
        /// </summary>
        public byte[] ToBytes()
        {
            // First, build the SMB2 header
            var header = new SMB2Header
            {
                Command = SMB2Constants.NegotiateCommand
            };

            // Calculate offsets and sizes
            int dialectsOffset = SMB2Header.Size + SMB2Constants.NegotiateRequestSize;
            int dialectsPaddingLength = (dialectsOffset + Dialects.Count * 2) % 8 == 0 ? 0 : 8 - ((dialectsOffset + Dialects.Count * 2) % 8);
            int contextOffset = dialectsOffset + Dialects.Count * 2 + dialectsPaddingLength;

            // Convert everything to bytes
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // NetBIOS header (will be updated at the end)
            var netBiosHeader = new NetBIOSHeader();
            writer.Write(netBiosHeader.ToBytes());

            // SMB2 header
            writer.Write(header.ToBytes());

            // Negotiate request body
            writer.Write(StructureSize);
            writer.Write((ushort)Dialects.Count);
            writer.Write(SecurityMode);
            writer.Write(Reserved);
            writer.Write(Capabilities);
            writer.Write(ClientGuid.ToByteArray());
            writer.Write(contextOffset);  // Negotiate context offset
            writer.Write((ushort)NegotiateContexts.Length);
            writer.Write((ushort)0);  // Reserved

            // Dialects
            foreach (var dialect in Dialects)
            {
                writer.Write((ushort)dialect);
            }

            // Padding to 8-byte boundary
            for (int i = 0; i < dialectsPaddingLength; i++)
            {
                writer.Write((byte)0);
            }

            // Negotiate contexts
            for (int i = 0; i < NegotiateContexts.Length; i++)
            {
                byte[] contextBytes = NegotiateContexts[i].ToBytes();
                writer.Write(contextBytes);

                // Pad to 8-byte boundary if there's another context (i.e. it's not the last one)
                if (i != NegotiateContexts.Length - 1)
                {
                    int contextPadding = contextBytes.Length % 8 == 0 ? 0 : 8 - (contextBytes.Length % 8);
                    for (int j = 0; j < contextPadding; j++)
                    {
                        writer.Write((byte)0);
                    }
                }
            }

            // Update NetBIOS header with correct length
            byte[] fullPacket = ms.ToArray();
            int smbLength = fullPacket.Length - 4;  // Subtract NetBIOS header
            fullPacket[1] = (byte)((smbLength >> 16) & 0xFF);
            fullPacket[2] = (byte)((smbLength >> 8) & 0xFF);
            fullPacket[3] = (byte)(smbLength & 0xFF);

            return fullPacket;
        }
    }
}
