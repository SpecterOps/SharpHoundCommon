using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB1
{
    /// <summary>
    /// Represents an SMB dialects of various predefined protocol versions
    /// </summary>
    /// <remarks>
    /// For more origin information, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/80850595-e301-4464-9745-58e4945eb99b">MS-CIFS 1.7 Versioning and Capability Negotiation</see>
    /// and
    /// <see href="https://github.com/samba-team/samba/blob/20129d16dc30a2ab9ad0ae04fec5cf007ebb035d/source3/smbd/smb1_negprot.c#L342-L417">smb1_ngprot.sc in the Samba project</see>
    /// </remarks>
    public sealed class SMBDialect : IEquatable<SMBDialect>
    {
        private readonly string _value;

        /// <summary>
        /// Private constructor prevents arbitrary instantiation
        /// </summary>
        /// <param name="value">The string representation of the dialect</param>
        private SMBDialect(string value)
        {
            _value = value;
        }

        #region Microsoft Specification Definitions
        /// <summary>
        /// PCLAN1.0 protocol dialect
        /// </summary>
        public static readonly SMBDialect PCLAN10 = new("PCLAN1.0");

        /// <summary>
        /// PC NETWORK PROGRAM 1.0 protocol dialect
        /// </summary>
        public static readonly SMBDialect PCNETWORKPROGRAM10 = new("PC NETWORK PROGRAM 1.0");

        /// <summary>
        /// xenix1.1 protocol dialect
        /// </summary>
        public static readonly SMBDialect XENIX11 = new("xenix1.1");

        /// <summary>
        /// XENIX CORE protocol dialect
        /// </summary>
        public static readonly SMBDialect XENIX1CORE = new("XENIX CORE");

        /// <summary>
        /// MICROSOFT NETWORKS 1.03 protocol dialect
        /// </summary>
        public static readonly SMBDialect COREPLUS = new("MICROSOFT NETWORKS 1.03");

        /// <summary>
        /// LANMAN1.0 protocol dialect
        /// </summary>
        public static readonly SMBDialect LANMANAGER10 = new("LANMAN1.0");

        /// <summary>
        /// MICROSOFT NETWORKS 3.0 protocol dialect
        /// </summary>
        public static readonly SMBDialect DOSLANMANAGER10 = new("MICROSOFT NETWORKS 3.0");

        /// <summary>
        /// LANMAN1.2 protocol dialect
        /// </summary>
        public static readonly SMBDialect LANMANAGER12 = new("LANMAN1.2");

        /// <summary>
        /// LM1.2X002 protocol dialect
        /// </summary>
        public static readonly SMBDialect LANMANAGER20 = new("LM1.2X002");

        /// <summary>
        /// DOS LM1.2X002 protocol dialect
        /// </summary>
        public static readonly SMBDialect DOSLANMANAGER20 = new("DOS LM1.2X002");

        /// <summary>
        /// LANMAN2.1 protocol dialect
        /// </summary>
        public static readonly SMBDialect LANMANAGER21 = new("LANMAN2.1");

        /// <summary>
        /// DOS LANMAN2.1 protocol dialect
        /// </summary>
        public static readonly SMBDialect DOSLANMANAGER21 = new("DOS LANMAN2.1");

        /// <summary>
        /// NT LM 0.12 protocol dialect (Common Internet File System)
        /// </summary>
        public static readonly SMBDialect NTLM012 = new("NT LM 0.12");

        // Defined in MS-SMB2 3.2.4.2.2.1 Multi-Protocol Negotiate
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8f8190fb-7e22-4dc0-8ae7-de2780674721
        /// <summary>
        /// SMB 2.002 protocol dialect
        /// </summary>
        public static readonly SMBDialect SMB2002 = new("SMB 2.002");

        /// <summary>
        /// SMB 2.??? protocol dialect
        /// </summary>
        public static readonly SMBDialect SMB2XXX = new("SMB 2.???");


        // The following is defined in MS-SMB2 in 4.1 Windows for Workgroups 3.1a
        /// <summary>
        /// Windows for Workgroups 3.1a protocol dialect
        /// 
        /// 
        /// </summary>
        public static readonly SMBDialect WINDOWSFORWORKGROUPS31 = new("Windows for Workgroups 3.1a");
        #endregion


        #region XP/2003 source code defined dialect

        /// <summary>
        /// Cairo 0.xa protocol dialect
        /// </summary>
        public static readonly SMBDialect CAIROX = new("Cairo 0.xa");

        /// <summary>
        /// NT LM 0.13 protocol dialect
        /// </summary>
        public static readonly SMBDialect NTLM013 = new("NT LM 0.13");
        #endregion


        /// <summary>
        /// Returns the string representation of the dialect
        /// </summary>
        /// <returns>The dialect name as a string</returns>
        public override string ToString() => _value;

        /// <summary>
        /// Determines whether this instance is equal to another SMBDialect
        /// </summary>
        /// <param name="other">The other SMBDialect to compare with</param>
        /// <returns>True if the dialects are equal, false otherwise</returns>
        public bool Equals(SMBDialect other) => _value == other._value;

        /// <summary>
        /// Determines whether this instance is equal to another object
        /// </summary>
        /// <param name="obj">The object to compare with</param>
        /// <returns>True if the objects are equal, false otherwise</returns>
        public override bool Equals(object obj) =>
            obj is SMBDialect other && Equals(other);

        /// <summary>
        /// Gets the hash code for this instance
        /// </summary>
        /// <returns>The hash code for the dialect</returns>
        public override int GetHashCode() => _value.GetHashCode();

        /// <summary>
        /// Equality operator for comparing two SMBDialect instances
        /// </summary>
        /// <param name="left">The left SMBDialect to compare</param>
        /// <param name="right">The right SMBDialect to compare</param>
        /// <returns>True if the dialects are equal, false otherwise</returns>
        public static bool operator ==(SMBDialect left, SMBDialect right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        /// Inequality operator for comparing two SMBDialect instances
        /// </summary>
        /// <returns>True if the dialects are not equal, false otherwise</returns>
        public static bool operator !=(SMBDialect left, SMBDialect right) =>
            !(left == right);
    }

}
