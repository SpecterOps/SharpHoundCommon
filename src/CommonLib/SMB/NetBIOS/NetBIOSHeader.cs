using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.NetBIOS
{
    /// <summary>
    /// Represents a NetBIOS header.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc1002#section-4.3">RFC 1002 Section 4.3 - SESSION SERVICE PACKETS</see>
    /// </para>
    /// </remarks>
    public class NetBIOSHeader
    {
        #region Structure Fields
        /// <summary>
        /// Gets or sets the message type (0x00 for Session Message)
        /// </summary>
        public NetBIOSSessionType Type { get; set; } = NetBIOSSessionType.SessionMessage;

        /// <summary>
        /// Gets or sets the length of the message following this header
        /// </summary>
        public int Length { get; set; } = 0;
        #endregion

        #region Constants
        /// <summary>
        /// Total size of the NetBIOS Header structure.
        /// </summary>
        public const int Size = 4;
        #endregion

        /// <summary>
        /// Converts the header to a byte array
        /// </summary>
        /// <returns>A byte array representing the NetBIOS header</returns>
        public byte[] ToBytes()
        {
            var bytes = new byte[4];
            bytes[0] = Type.Value;
            bytes[1] = (byte)((Length >> 16) & 0xFF);
            bytes[2] = (byte)((Length >> 8) & 0xFF);
            bytes[3] = (byte)(Length & 0xFF);
            return bytes;
        }

        /// <summary>
        /// Creates a NetBiosHeader from a byte array
        /// </summary>
        /// <param name="bytes">The byte array containing the NetBIOS header data</param>
        /// <param name="offset">The offset within the byte array where the header begins</param>
        /// <returns>A NetBiosHeader object parsed from the byte array</returns>
        public static NetBIOSHeader FromBytes(byte[] bytes, int offset = 0)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (offset < 0 || offset + 4 > bytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset),
                    "Offset is negative or there aren't enough bytes to parse the NetBIOS header");

            return new NetBIOSHeader
            {
                Type = NetBIOSSessionType.FromByte(bytes[offset]),
                Length = (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]
            };
        }
    }
}
