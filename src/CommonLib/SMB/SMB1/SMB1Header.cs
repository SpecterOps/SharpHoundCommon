using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB1
{
    /// <summary>
    /// Protocol header structure used in SMB1 messages.
    /// Default values align with the values sent on Windows 11.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f">MS-CIFS 2.2.3.1 The SMB Header</see>
    /// </para>
    /// </remarks>
    public class SMB1Header
    {
        #region SMB Header Fields
        /// <summary>
        /// Gets or sets the SMB protocol identifier. Should be 0xFF, 'S', 'M', 'B'.
        /// </summary>
        public byte[] Protocol { get; set; } = SpecificationProtocolIdBytes;

        /// <summary>
        /// Gets or sets the SMB command.
        /// </summary>
        public byte Command { get; set; }

        /// <summary>
        /// Gets or sets the status of the request/response.
        /// </summary>
        public uint Status { get; set; }

        /// <summary>
        /// Gets or sets the SMB flags for this message.
        /// </summary>
        public SMB1Flags Flags { get; set; }

        /// <summary>
        /// Gets or sets the SMB flags2 for this message.
        /// </summary>
        public SMB1Flags2 Flags2 { get; set; }

        /// <summary>
        /// Gets or sets the high portion of the process ID.
        /// </summary>
        public ushort PidHigh { get; set; }

        /// <summary>
        /// Gets or sets the security signature for the message.
        /// </summary>
        public ulong SecurityFeatures { get; set; }

        /// <summary>
        /// Gets or sets a reserved field (must be 0).
        /// </summary>
        public ushort Reserved { get; set; }

        /// <summary>
        /// Gets or sets the tree ID (TID) for the message.
        /// </summary>
        public ushort TreeId { get; set; }

        /// <summary>
        /// Gets or sets the process ID for the message.
        /// </summary>
        public ushort PidLow { get; set; }

        /// <summary>
        /// Gets or sets the user ID (UID) for the message.
        /// </summary>
        public ushort UserId { get; set; }

        /// <summary>
        /// Gets or sets the multiplex ID (MID) for the message.
        /// </summary>
        public ushort MultiplexId { get; set; }

        #endregion

        #region SMB1 Constants
        /// <summary>
        /// SMB1 protocol identifier defined in the MS-CIFS specification
        /// </summary>
        public const uint SpecificationProtocolId = 0x424D53FF;

        /// <summary>
        /// SMB1 protocol identifier defined in the MS-CIFS specification
        /// </summary>
        public static readonly byte[] SpecificationProtocolIdBytes = [0xFF, (byte)'S', (byte)'M', (byte)'B'];

        /// <summary>
        /// Size of the SMB1 header in bytes.
        /// </summary>
        public const int Size = 32;
        #endregion


        /// <summary>
        /// Writes the SMB header to a binary writer.
        /// </summary>
        /// <param name="writer">The binary writer to write to.</param>
        public void WriteTo(BinaryWriter writer)
        {
            if (writer == null)
                throw new ArgumentNullException(nameof(writer));

            writer.Write(Protocol);
            writer.Write(Command);
            writer.Write(Status);
            writer.Write((byte)Flags);
            writer.Write((ushort)Flags2);
            writer.Write(PidHigh);
            writer.Write(SecurityFeatures);
            writer.Write(Reserved);
            writer.Write(TreeId);
            writer.Write(PidLow);
            writer.Write(UserId);
            writer.Write(MultiplexId);
        }

        /// <summary>
        /// Serializes the SMB header to a byte array.
        /// </summary>
        /// <returns>A byte array containing the SMB header.</returns>
        public byte[] ToBytes()
        {
            using var memoryStream = new MemoryStream(Size);
            using var writer = new BinaryWriter(memoryStream, Encoding.ASCII);

            WriteTo(writer);

            return memoryStream.ToArray();
        }

        /// <summary>
        /// Parses an SMB header from a byte array.
        /// </summary>
        /// <param name="data">The byte array containing the SMB header.</param>
        /// <returns>An SMB header parsed from the byte array.</returns>
        public static SMB1Header FromBytes(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (data.Length < Size)
                throw new ArgumentException($"Data array must be at least {Size} bytes", nameof(data));

            using var memoryStream = new MemoryStream(data);
            using var reader = new BinaryReader(memoryStream);

            return FromBytes(reader);
        }

        /// <summary>
        /// Parses an SMB header from a binary reader.
        /// Only validates the Protocol field's value.
        /// </summary>
        /// <param name="reader">The binary reader to read from.</param>
        public static SMB1Header FromBytes(BinaryReader reader)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            var header = new SMB1Header
            {
                Protocol = reader.ReadBytes(4)
            };

            if (header.Protocol.Length != 4 || !header.Protocol.SequenceEqual(SpecificationProtocolIdBytes))
            {
                throw new InvalidDataException("Invalid SMB protocol identifier: " + BitConverter.ToString(header.Protocol));
            }

            header.Command = reader.ReadByte();
            header.Status = reader.ReadUInt32();
            header.Flags = (SMB1Flags)reader.ReadByte();
            header.Flags2 = (SMB1Flags2)reader.ReadUInt16();
            header.PidHigh = reader.ReadUInt16();
            header.SecurityFeatures = reader.ReadUInt64();
            header.Reserved = reader.ReadUInt16();
            header.TreeId = reader.ReadUInt16();
            header.PidLow = reader.ReadUInt16();
            header.UserId = reader.ReadUInt16();
            header.MultiplexId = reader.ReadUInt16();

            return header;
        }
    }

}
