using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// SMB2 RDMA Transform Types
    /// </summary>
    public enum SMB2RdmaTransformType : ushort
    {
        None = 0x0000,
        Encryption = 0x0001,
        Signing = 0x0002
    }
}
