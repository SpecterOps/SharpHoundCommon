using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// Represents an SMB2 header
    /// </summary>
    /// <remarks>
    /// For definition, see
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4">MS-SMB2 2.2.1.2 SMB2 Packet Header - SYNC</see>
    /// </remarks>
    public class SMB2Header
    {
        #region Structure Fields
        public uint ProtocolId { get; set; } = SpecificationProtocolId;
        public ushort StructureSize { get; set; } = Size;
        public ushort CreditCharge { get; set; } = 0;
        public uint StatusOrChannelSequence { get; set; } = 0;
        public ushort Command { get; set; } = 0;

        /// <summary>
        /// Indicates the number of credits the client is requesting.
        /// On a response, it indicates the number of credits granted to the client.
        /// </summary>
        public ushort CreditsRequestResponse { get; set; } = 1;
        public uint Flags { get; set; } = 0;

        /// <summary>
        /// For a compounded request and response, this field MUST be set to the
        /// offset, in bytes, from the beginning of this SMB2 header to the start of the subsequent 8-byte
        /// aligned SMB2 header.If this is not a compounded request or response, or this is the last header in
        /// a compounded request or response, this value MUST be 0.
        /// 
        /// Wireshark labels parses this as Chain Offset
        /// </summary>
        public uint NextCommand { get; set; } = 0;
        public ulong MessageId { get; set; } = 0;
        public uint Reserved { get; set; } = 0;
        public uint TreeId { get; set; } = 0xFFFE0000;
        public ulong SessionId { get; set; } = 0;
        public byte[] Signature { get; set; } = new byte[16]; // 16 bytes of zeros
        #endregion

        #region Constants
        /// <summary>
        /// Size of the SMB2 header in bytes.
        /// </summary>
        public const int Size = 64;

        /// <summary>
        /// Protocol identifier defined in the MS-CIFS specification
        /// </summary>
        public const uint SpecificationProtocolId = 0x424D53FE; // "\xFESMB"

        /// <summary>
        /// SMB1 protocol identifier defined in the MS-CIFS specification
        /// </summary>
        public static readonly byte[] SpecificationProtocolIdBytes = [0xFE, (byte)'S', (byte)'M', (byte)'B'];
        #endregion

        /// <summary>
        /// Converts the header to a byte array
        /// </summary>
        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(ProtocolId);
            writer.Write(StructureSize);
            writer.Write(CreditCharge);
            writer.Write(StatusOrChannelSequence);
            writer.Write(Command);
            writer.Write(CreditsRequestResponse);
            writer.Write(Flags);
            writer.Write(NextCommand);
            writer.Write(MessageId);
            writer.Write(Reserved);
            writer.Write(TreeId);
            writer.Write(SessionId);
            writer.Write(Signature);

            return ms.ToArray();
        }


        public static SMB2Header FromBytes(byte[] data, int offset)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset cannot be negative");

            if (data.Length - offset < Size)
                throw new ArgumentException($"Data array must have at least {Size} bytes available starting at offset {offset}", nameof(data));

            using var memoryStream = new MemoryStream(data, offset, Size);
            using var reader = new BinaryReader(memoryStream);

            return FromBytes(reader);
        }


        public static SMB2Header FromBytes(BinaryReader reader)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            var header = new SMB2Header
            {
                ProtocolId = reader.ReadUInt32(),
                StructureSize = reader.ReadUInt16(),
                CreditCharge = reader.ReadUInt16(),
                StatusOrChannelSequence = reader.ReadUInt32(),
                Command = reader.ReadUInt16(),
                CreditsRequestResponse = reader.ReadUInt16(),
                Flags = reader.ReadUInt32(),
                NextCommand = reader.ReadUInt32(),
                MessageId = reader.ReadUInt64(),
                Reserved = reader.ReadUInt32(),
                TreeId = reader.ReadUInt32(),
                SessionId = reader.ReadUInt64()
            };

            // Validate protocol ID
            if (header.ProtocolId != SpecificationProtocolId)
            {
                throw new ArgumentException($"Invalid SMB2 protocol ID: 0x{header.ProtocolId:X8}");
            }

            // Read the 16-byte signature
            header.Signature = reader.ReadBytes(16);

            return header;
        }
    }

}
