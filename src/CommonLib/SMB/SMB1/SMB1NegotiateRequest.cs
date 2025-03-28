using SharpHoundCommonLib.SMB.NetBIOS;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB1
{
    /// <summary>
    /// Represents an SMB1 Negotiate request message.
    /// Used to initiate an SMB connection and determine which dialect to use.
    /// Default values represent what is sent by default on a Windows 11 machine.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f">MS-CIFS 2.2.3.1 The SMB Header</see>
    /// </para>
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/25c8c3c9-58fc-4bb8-aa8f-0272dede84c5">MS-SMB 2.2.4.52.1 SMB_COM_NEGOTIATE Request</see>
    /// </para>
    /// </remarks>
    public class SMB1NegotiateRequest
    {
        /// <summary>
        /// Gets or sets the SMB header for this request.
        /// </summary>
        public SMB1Header Header { get; private set; }


        #region Negotiate Request Fields (see MS-CIFS 2.2.4.52.1 Request)
        /// <summary>
        /// Gets or sets the word count value (0 for Negotiate request)
        /// </summary>
        public byte WordCount { get; set; } = 0; // 0 for Negotiate request

        /// <summary>
        /// Gets or sets the byte count value for dialect data
        /// </summary>
        public ushort DialectByteCount { get; private set; }

        private SMBDialect[] _dialects =
        [
            SMBDialect.NTLM012,
            SMBDialect.SMB2002,
            SMBDialect.SMB2XXX,
        ];

        /// <summary>
        /// Gets or sets the array of SMB dialects to negotiate.
        /// Updates ByteCount automatically when modified.
        /// Using an array prevents modifications without triggering the setter.
        /// </summary>
        public SMBDialect[] Dialects
        {
            get => _dialects;
            set
            {
                _dialects = value ?? throw new ArgumentNullException(nameof(value), "Dialects cannot be null");
                // Update DialectByteCount whenever Dialects are changed
                DialectByteCount = CalculateDialectsByteCount();
            }
        }
        #endregion

        /// <summary>
        /// Creates a new SMB1NegotiateRequest with default values
        /// </summary>
        public SMB1NegotiateRequest()
        {
            // Initialize header with default values for a negotiate request
            // as seen on Windows 11
            Header = new SMB1Header()
            {
                Command = SMB1Command.Negotiate,
                Status = 0,
                Flags = SMB1Flags.CanonicalizedPaths | SMB1Flags.CaseSensitive, // 0x18
                Flags2 = SMB1Flags2.Unicode |
                         SMB1Flags2.NTStatus |
                         SMB1Flags2.ExtendedSecurityNeeded |
                         SMB1Flags2.LongNameUsed |
                         SMB1Flags2.SecuritySignaturesRequired |
                         SMB1Flags2.ExtendedAttributes |
                         SMB1Flags2.LongNames, // 0xC853
                PidHigh = 0,
                SecurityFeatures = 0,
                Reserved = 0,
                TreeId = 0xFFFF,
                PidLow = 0xFEFF,
                UserId = 0,
                MultiplexId = 0
            };

            // Initialize DialectByteCount based on default dialects
            DialectByteCount = CalculateDialectsByteCount();
        }

        /// <summary>
        /// Calculates the byte count based on the dialects array
        /// </summary>
        /// <returns>The calculated byte count</returns>
        private ushort CalculateDialectsByteCount()
        {
            int byteCount = 0;
            foreach (var dialect in _dialects)
            {
                byteCount += 1; // Buffer format byte
                byteCount += Encoding.ASCII.GetByteCount(dialect.ToString());
                byteCount += 1; // Null terminator
            }
            return (ushort)byteCount;
        }

        /// <summary>
        /// Gets the total size of the SMB message in bytes (excluding the NetBIOS header)
        /// </summary>
        public int SmbMessageSize
        {
            get
            {
                return
                    SMB1Header.Size // SMB Header Size (32)
                    + 3 // Negotiate Request size: WordCount(1) + ByteCount(2)
                    + DialectByteCount;
            }
        }

        /// <summary>
        /// Serializes the SMB1NegotiateRequest to a byte array
        /// </summary>
        /// <returns>A byte array containing the complete SMB1 Negotiate Request message</returns>
        public byte[] ToBytes()
        {
            using var memoryStream = new MemoryStream();
            using var writer = new BinaryWriter(memoryStream, Encoding.ASCII);

            var netBiosHeader = new NetBIOSHeader
            {
                Length = SmbMessageSize
            };

            writer.Write(netBiosHeader.ToBytes());

            // Write SMB Header
            Header.WriteTo(writer);

            // Write Negotiate Request specific fields
            writer.Write(WordCount);
            writer.Write(DialectByteCount);

            foreach (var dialect in _dialects)
            {
                //  0x2 == Dialect String (null terminated ascii string)
                // See MS-CIFS 2.2.2.5 Data Buffer Format Codes
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/9189a82f-c1c0-4af9-818c-85050f7e5e66
                writer.Write((byte)2);
                writer.Write(Encoding.ASCII.GetBytes(dialect.ToString()));
                writer.Write((byte)0); // Null terminator
            }

            return memoryStream.ToArray();
        }

        /// <summary>
        /// Writes the SMB1NegotiateRequest to a stream
        /// </summary>
        /// <param name="stream">The stream to write to</param>
        public void WriteTo(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = ToBytes();
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously writes the SMB1NegotiateRequest to a stream
        /// </summary>
        /// <param name="stream">The stream to write to</param>
        /// <param name="cancellationToken">A cancellation token for the operation</param>
        /// <returns>A task representing the asynchronous write operation</returns>
        public async Task WriteToAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = ToBytes();
            await stream.WriteAsync(data, 0, data.Length, cancellationToken);
            await stream.FlushAsync();
        }
    }
}
