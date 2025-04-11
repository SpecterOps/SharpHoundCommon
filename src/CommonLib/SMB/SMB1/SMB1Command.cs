using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB1
{
    /// <summary>
    /// SMB1 command codes. 
    /// Place holder class for future commands that may be used.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/5cd5747f-fe0b-40a6-89d0-d67f751f8232">MS-CIFS 2.2.4 SMB Commands</see>
    /// </para>
    /// </remarks>
    public class SMB1Command
    {
        /// <summary>
        /// SMB_COM_NEGOTIATE (0x72).
        /// This command is used to initiate an SMB connection between the client and the server.
        /// </summary>
        public static byte Negotiate = 0x72;
    }
}
