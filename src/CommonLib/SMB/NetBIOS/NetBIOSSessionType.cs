using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.NetBIOS
{
    /// <summary>
    /// Message type of the NetBIOS Service Session.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc1002#section-4.3.1">RFC 1002 Section 4.3.1 - GENERAL FORMAT OF SESSION PACKETS</see>
    /// </para>
    /// </remarks>
    public class NetBIOSSessionType
    {
        /// <summary>
        /// Gets the raw byte value of the NetBios session type
        /// </summary>
        public byte Value { get; private set; }

        /// <summary>
        /// Private constructor prevents arbitrary instantiation
        /// </summary>
        /// <param name="value">The byte value of the session type</param>
        private NetBIOSSessionType(byte value)
        {
            Value = value;
        }

        /// <summary>
        /// NetBIOS Session Message type (0x00)
        /// </summary>
        public static readonly NetBIOSSessionType SessionMessage = new(0x00);

        /// <summary>
        /// NetBIOS Session Request type (0x81)
        /// </summary>
        public static readonly NetBIOSSessionType SessionRequest = new(0x81);

        /// <summary>
        /// NetBIOS Positive Session Response (0x82)
        /// </summary>
        public static readonly NetBIOSSessionType PositiveSessionResponse = new(0x82);

        /// <summary>
        /// NetBIOS Negative Session Response (0x83)
        /// </summary>
        public static readonly NetBIOSSessionType NegativeSessionResponse = new(0x83);

        /// <summary>
        /// NetBIOS Retarget Session Response (0x84)
        /// </summary>
        public static readonly NetBIOSSessionType RetargetSessionResponse = new(0x84);

        /// <summary>
        /// NetBIOS Session Keep Alive (0x85)
        /// </summary>
        public static readonly NetBIOSSessionType SessionKeepAlive = new(0x85);

        /// <summary>
        /// Gets a NetBiosSessionType instance by its byte value
        /// </summary>
        /// <param name="value">The byte value of the session type</param>
        /// <returns>A NetBiosSessionType instance corresponding to the value, or a new instance for unknown types</returns>
        public static NetBIOSSessionType FromByte(byte value)
        {
            return value switch
            {
                0x00 => SessionMessage,
                0x81 => SessionRequest,
                0x82 => PositiveSessionResponse,
                0x83 => NegativeSessionResponse,
                0x84 => RetargetSessionResponse,
                0x85 => SessionKeepAlive,
                _ => new NetBIOSSessionType(value) // Allow unknown types
            };
        }

        /// <summary>
        /// Returns the string representation of the session type
        /// </summary>
        /// <returns>The session type value as a string</returns>
        public override string ToString() => Value.ToString();

        /// <summary>
        /// Determines whether this instance is equal to another NetBiosSessionType
        /// </summary>
        /// <param name="other">The other NetBiosSessionType to compare with</param>
        /// <returns>True if the session types are equal, false otherwise</returns>
        public bool Equals(NetBIOSSessionType? other) =>
            other != null && Value == other.Value;

        /// <summary>
        /// Determines whether this instance is equal to another object
        /// </summary>
        /// <param name="obj">The object to compare with</param>
        /// <returns>True if the objects are equal, false otherwise</returns>
        public override bool Equals(object? obj) =>
            obj is NetBIOSSessionType other && Equals(other);

        /// <summary>
        /// Gets the hash code for this instance
        /// </summary>
        /// <returns>The hash code for the session type</returns>
        public override int GetHashCode() => Value.GetHashCode();

        /// <summary>
        /// Equality operator for comparing two NetBiosSessionType instances
        /// </summary>
        /// <param name="left">The left NetBiosSessionType to compare</param>
        /// <param name="right">The right NetBiosSessionType to compare</param>
        /// <returns>True if the session types are equal, false otherwise</returns>
        public static bool operator ==(NetBIOSSessionType? left, NetBIOSSessionType? right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        /// Inequality operator for comparing two NetBiosSessionType instances
        /// </summary>
        /// <param name="left">The left NetBiosSessionType to compare</param>
        /// <param name="right">The right NetBiosSessionType to compare</param>
        /// <returns>True if the session types are not equal, false otherwise</returns>
        public static bool operator !=(NetBIOSSessionType? left, NetBIOSSessionType? right) =>
            !(left == right);
    }
}
